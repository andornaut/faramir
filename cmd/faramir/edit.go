package main

// `faramir vault edit` changes a managed sops file once the secrets directory belongs
// to the secrets group and the operator does not. It runs sops itself rather
// than asking the keeper, which has no operation that returns key material;
// under sudo this process is already root.
//
// Over running sops by hand it adds: plaintext that is 0600 root in a tmpfs
// rather than readable by the uid the agent runs as; an editor this process
// chose, never one $EDITOR named; a path argument that cannot leave the managed
// set; and an audit record.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// sopsBinary is resolved through PATH. A variable so a test can point it
// elsewhere.
var sopsBinary = "sops"

// editors are tried in order when none is given. Absolute paths only:
// "sensible-editor" and "editor" resolve through files the operator can write.
var editors = []string{
	"/usr/bin/nano",
	"/bin/nano",
	"/usr/bin/vim",
	"/usr/bin/vi",
	"/bin/vi",
}

type editFlags struct {
	editor string
}

func newEditCmd() *cobra.Command {
	var f editFlags
	c := &cobra.Command{
		Use:   "edit [options] FILE",
		Short: "Edit a managed sops file",
		Args:  exactlyOneArg("file"),
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runEdit(f, args)) },
	}
	c.Flags().StringVar(&f.editor, "editor", "", "absolute path to the editor to run (default: the first of "+
		strings.Join(editors, ", ")+" that exists)")
	return c
}

func runEdit(f editFlags, args []string) int {

	// Blocked rather than attempted: the bare permission error on the age key
	// does not say what to do.
	if !requireRoot("vault edit", "the age key is readable only by the keeper and by root") {
		return 1
	}

	cfg, err := config.Load(resolveConfig(socketDefault()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		return 1
	}

	// Expanded here, the managed store holding globs and this process being root,
	// so a file dropped into the secrets directory is editable at once. Both
	// kinds of failure together: this is printed when the named file is not among
	// the managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	unresolvable := slices.Concat(failures, absent)
	target, err := resolveManaged(managed, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}

	editorPath, err := resolveEditor(f.editor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		return 1
	}

	keyPath := ageKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: age key: %v\n", err)
		return 1
	}

	// The install's own rules, named rather than left to sops to find: see
	// runSops. The same file `reseal` reads, so the two agree about what governs
	// a managed file.
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")

	changed, err := editManaged(keyPath, rulePath, editorPath, target)
	record := map[string]any{
		"op": opEdit,
		// "log_id", the spelling the broker writes and the only one `faramir logs`
		// reads: it is what the record is looked up and sorted by.
		"log_id": audit.NewLogID(),
		"file":   target,
		"editor": editorPath,
		"uid":    os.Getuid(),
		"sudo":   os.Getenv("SUDO_USER"),
	}
	if err != nil {
		record["error"] = err.Error()
	} else {
		record["changed"] = changed
	}
	// The file and whether it changed, never what is in it.
	audit.NewLog(cfg.Audit).Write(record, audit.Output{})

	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "faramir vault edit: unchanged")
		return 0
	}
	fmt.Fprintf(os.Stderr, "faramir vault edit: wrote %s; the broker picks it up within one refresh interval\n", target)
	return 0
}

// resolveConfig finds the config a client command has to agree with:
// $FARAMIR_CONFIG, then whatever discoverConfigFile finds, then the compiled
// default if it is there. No command takes a path: a caller cannot be expected
// to know where the config lives, and every one of them can ask the broker.
// An explicit $FARAMIR_CONFIG returns empty, the variable being config.Load's
// to read.
func resolveConfig(socketPath string) string {
	if os.Getenv("FARAMIR_CONFIG") != "" {
		return ""
	}
	return installedConfig(discoverConfigFile(askBroker(socketPath)))
}

// resolveDaemonConfig is resolveConfig for the three daemon entry points, which
// under systemd are pointed at their config by FARAMIR_CONFIG in the unit.
//
// The running broker is not a step here, unlike resolveConfig: this process may
// be about to bind the broker's own socket, and connecting to it would
// socket-activate the installed daemon and leave the two contending for the
// path. The unit answers the same question without the round trip.
func resolveDaemonConfig() string {
	if os.Getenv("FARAMIR_CONFIG") != "" {
		return ""
	}
	return installedConfig(unitConfigFile())
}

// installedConfig takes what discovery found, and falls back to the compiled-in
// default only when that file is there. An empty result is left to
// config.Load, whose error for a host with no install is the one to print.
func installedConfig(found string) string {
	if found != "" {
		return found
	}
	if path := filepath.Join(install.DefaultConfigDir, "config.toml"); exists(path) {
		return path
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// errNoManagedFiles is what `edit` reports when the secrets directory is empty.
// `reseal` has its own, saying what it in particular had nothing to do.
var errNoManagedFiles = errors.New("no managed sops files: the managed store named " +
	"none, so there is nothing to open. Write the first one with `faramir vault " +
	"add NAME`")

// managedSuffix is what a managed file ends in. One spelling: the suffix
// decides the store format sops writes and is what the [secret] pattern
// matches, so it stays on the file and off the argument.
const managedSuffix = ".sops.yml"

// managedSuffixes is what a name already spelled in full ends in. A write always
// produces managedSuffix, but a [secret] pattern may name any of these, so a name
// carrying one is the operator naming the file rather than the stem of one.
var managedSuffixes = []string{managedSuffix, ".sops.yaml", ".sops.json"}

// carriesManagedSuffix reports whether this is already a managed file's name.
// Asked separately from the [secret] patterns: a name may end in a managed
// suffix and still match no pattern, and appending a second suffix to that one
// refuses it under a name the operator never typed.
func carriesManagedSuffix(path string) bool {
	for _, suffix := range managedSuffixes {
		if strings.HasSuffix(path, suffix) {
			return true
		}
	}
	return false
}

// managedStem is a managed file's name without its suffix, which is what an
// operator types.
func managedStem(path string) string {
	stem, _ := strings.CutSuffix(filepath.Base(path), managedSuffix)
	return stem
}

// resolveManaged maps the argument onto one of the configured files, matching a
// bare name against each base name and against each name without its suffix.
// Anything unmanaged is refused, an edit outside the list being a file the
// broker never reads.
func resolveManaged(managed []string, arg string) (string, error) {
	if len(managed) == 0 {
		return "", errNoManagedFiles
	}
	var matches []string
	wanted := filepath.Clean(arg)
	for _, file := range managed {
		if filepath.Clean(file) == wanted || filepath.Base(file) == arg ||
			managedStem(file) == arg {
			matches = append(matches, file)
		}
	}
	switch len(matches) {
	case 1:
		return matches[0], nil
	case 0:
		return "", fmt.Errorf("%s is not a managed file; the managed store names %s",
			arg, strings.Join(managed, ", "))
	default:
		return "", fmt.Errorf("%s matches more than one managed file (%s); name the full path",
			arg, strings.Join(matches, ", "))
	}
}

// resolveEditor takes the requested editor or the first candidate that exists.
// Absolute either way, so what runs as root does not depend on an inherited
// PATH.
func resolveEditor(requested string) (string, error) {
	if requested != "" {
		if !filepath.IsAbs(requested) {
			return "", fmt.Errorf("editor %q must be an absolute path", requested)
		}
		info, err := os.Stat(requested)
		if err != nil {
			return "", fmt.Errorf("editor %s: %w", requested, err)
		}
		if reason := unsafeToRunAsRoot(requested, info); reason != "" {
			return "", fmt.Errorf("editor %s: %s", requested, reason)
		}
		return requested, nil
	}
	for _, candidate := range editors {
		if _, err := os.Stat(candidate); err == nil {
			return candidate, nil
		}
	}
	return "", fmt.Errorf("no editor found; install one of %s or pass --editor",
		strings.Join(editors, ", "))
}

// unsafeToRunAsRoot names why this file must not be the editor, or "" if it may
// be. The editor runs as root with the decrypted store open, so a file the
// operator can write is the operator choosing what runs as root. The directory
// counts as much as the file: write there is permission to replace it.
func unsafeToRunAsRoot(path string, info os.FileInfo) string {
	if !info.Mode().IsRegular() {
		return "not a regular file"
	}
	for _, at := range []string{path, filepath.Dir(path)} {
		stat, ok := mustStat(at)
		if !ok {
			return "cannot read the owner of " + at
		}
		if stat.Uid != 0 {
			return fmt.Sprintf("%s belongs to uid %d rather than root, which is the "+
				"account that would then choose what runs as root", at, stat.Uid)
		}
		if mode := os.FileMode(stat.Mode).Perm(); mode&0o022 != 0 {
			return fmt.Sprintf("%s is %04o: an account that is not root can replace "+
				"what runs here", at, mode)
		}
	}
	return ""
}

func mustStat(path string) (*syscall.Stat_t, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

// editManaged decrypts, edits and re-encrypts one file in place, and reports
// whether the plaintext changed. Two sops runs rather than its own `sops FILE`
// mode, which picks the editor out of the environment.
func editManaged(keyPath, rulePath, editorPath, target string) (bool, error) {
	// A tmpfs, so the plaintext never reaches a disk, and 0700 from MkdirTemp
	// keeps every other uid out while the editor has it open.
	dir, err := os.MkdirTemp("/dev/shm", "faramir-edit-")
	if err != nil {
		return false, fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last: defers unwind LIFO, and uninstalling the
	// handler before the directory is gone leaves a window where a signal kills
	// this process with the decrypted store still in place.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
	plain := filepath.Join(dir, filepath.Base(target))

	// The recipients the file already had, named explicitly: an edit preserves
	// who could read the file, and applying a changed .sops.yaml is what `faramir
	// recipient reseal` is for. Read before the editor runs, or a file whose
	// metadata this cannot parse would be reported after the operator's edit had
	// already been made and discarded.
	recipients, err := sopsrule.SealedTo(target)
	if err != nil {
		return false, err
	}

	// Asked here for the same reason: sops refuses a file no creation rule covers
	// at the encrypt, which is after the editor has run and would cost the
	// operator everything they typed.
	if err := ruleMustCover(rulePath, target, recipients); err != nil {
		return false, err
	}

	decrypted, err := runSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return false, fmt.Errorf("decrypt %s: %w", target, err)
	}
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return false, err
	}

	cmd := exec.CommandContext(context.Background(), editorPath, plain)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Fixed: the editor runs as root, and the operator can set every variable one
	// reads for configuration.
	cmd.Env = []string{envPATH,
		"TERM=" + os.Getenv("TERM"), envLANG, "HOME=" + dir}
	if err := cmd.Run(); err != nil {
		return false, fmt.Errorf("editor: %w", err)
	}

	edited, err := os.ReadFile(plain)
	if err != nil {
		return false, err
	}
	if string(edited) == string(decrypted) {
		return false, nil
	}

	reencrypted, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		// Said plainly: the plaintext goes with the tmpfs directory, and keeping it
		// would leave a decrypted store on the machine after a failed command.
		return false, fmt.Errorf("encrypt: %w. The edit was not saved and the "+
			"decrypted copy has been removed, so make it again once this is fixed", err)
	}
	return true, writeBack(target, reencrypted)
}

// writeBack replaces the managed file without changing who owns it, written
// beside the target and renamed so a partial failure leaves no truncated store.
//
// Both halves are made durable before this returns, this being the one
// operation that overwrites the only copy of the secrets on the host: the
// contents are flushed before the rename, or a crash leaves the new name
// pointing at a file whose data never landed, and the directory after it, or
// the rename itself is what is missing.
//
// The mode before the owner: the temporary file is created 0600 and root's, so
// widening it while it is still root:root gives nothing away.
func writeBack(target string, data []byte) error {
	info, err := os.Stat(target)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(target), filepath.Base(target)+".*")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if err := chownLike(tmp.Name(), info); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	// Reported and not returned: by here the replacement is the file, and what
	// failed is the promise that it survives a power loss. An error would tell
	// the operator their edit did not take, and would have `reseal` count the file
	// among those still sealed to the recipients they had.
	if err := syncDir(filepath.Dir(target)); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s was replaced, but %s could not be "+
			"flushed (%v), so the change may not survive a power loss until "+
			"something else syncs that filesystem\n",
			target, filepath.Dir(target), err)
	}
	return nil
}

// syncDir flushes a directory entry, which is what makes a rename survive a
// power loss rather than only a process dying.
func syncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}

// runSops execs sops with the key as a path (SOPS_AGE_KEY_FILE), as the keeper
// supplies it, so it is absent from any environment block in /proc. A fixed
// environment, sops reading several variables that name a key or key source.
//
// --config names the creation rules, which keeps them this host's own. Left to
// search, sops walks up from the process's working directory, which is often an
// enrolled tree the coding agent writes, and a .sops.yaml found there governs
// the encryption: `unencrypted_regex` and `unencrypted_suffix` make sops write
// the values they name in cleartext. Recipients are safe either way, the --age
// on the command line winning over a rule.
//
// The flag rather than the SOPS_CONFIG variable: a sops old enough not to know
// the variable ignores it and searches anyway, where an argument it does not
// understand is an error.
func runSops(keyPath, rulePath string, args ...string) ([]byte, error) {
	argv := append([]string{"--config", sopsConfigPath(rulePath)}, args...)
	cmd := exec.CommandContext(context.Background(), sopsBinary, argv...)
	cmd.Env = []string{
		envPATH,
		"HOME=" + envOr("HOME", "/tmp"),
		envLANG,
		"SOPS_AGE_KEY_FILE=" + keyPath,
	}
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// sopsConfigPath is the creation rules to hand sops, and /dev/null where there
// are none. A rule file that is not there is not the same as none: sops
// refuses to start on a --config it cannot read, decrypt included, where
// /dev/null parses as a document with no creation rules.
func sopsConfigPath(rulePath string) string {
	if rulePath != "" && exists(rulePath) {
		return rulePath
	}
	return os.DevNull
}

// ruleMustCover refuses an edit the creation rules cannot write back, or nil.
// A host with no rule encrypts with sops' defaults, which cover every file, and
// sopsConfigPath has already turned that into /dev/null.
//
// A probe that cannot be put is not a refusal: what is ruled out is the case
// certain to fail later.
func ruleMustCover(rulePath, target string, recipients []string) error {
	configPath := sopsConfigPath(rulePath)
	if configPath == os.DevNull {
		return nil
	}
	if err := ruleMustNotSplitTheKey(rulePath); err != nil {
		return err
	}
	// Covered unless the probe says otherwise, which is what makes a probe that
	// cannot be put leave the edit alone.
	covered := true
	if sops, err := exec.LookPath(sopsBinary); err == nil {
		if answer, err := sopsrule.Covers(sops, configPath, recipients, target); err == nil {
			covered = answer
		}
	}
	if covered {
		return nil
	}
	return fmt.Errorf("%s has no creation rule matching %s, so sops would refuse "+
		"to write it back and the edit would be lost at the end rather than now. "+
		"Widen path_regex to reach it, or keep the store where the rule already "+
		"looks; `faramir doctor` reports this under `rule coverage`", rulePath, target)
}

// ruleMustNotSplitTheKey refuses an edit under a rule that splits the data key,
// or nil. The refusal `faramir recipient reseal` makes, one step earlier:
// shamir_threshold means N of the rule's key groups have to come together to
// open a file, and what an edit writes back is sealed to the recipients the
// file already carried, as one group. sops writes the threshold beside that
// single group, so any one of those keys then opens the file.
func ruleMustNotSplitTheKey(rulePath string) error {
	// A rule this cannot read leaves rules empty and nothing to refuse: the same
	// file reaches sops next, and what sops says about it is the better answer.
	rules, _ := sopsrule.Load(rulePath)
	for _, rule := range rules {
		if rule.ShamirThreshold > 0 {
			return fmt.Errorf("%s sets shamir_threshold, so the data key is split "+
				"across key groups and %d of them are needed together. Writing this file "+
				"back would seal it to one group holding every key, and any one of them "+
				"would then open it, so this edit was refused rather than made. Use sops "+
				"directly for a store kept this way", rulePath, rule.ShamirThreshold)
		}
	}
	return nil
}

// sealTo encrypts the plaintext copy of target and returns the ciphertext.
//
// --filename-override, because sops matches a creation rule's path_regex
// against the file it is handed, taken relative to the rule file, and what it
// is handed here is the copy in the tmpfs: a rule naming where the secrets live
// would match nothing. With the override the rule sees `secrets/<name>`, as it
// does under ordinary use.
//
// The recipients are named here rather than taken from the rule, which is what
// makes an edit preserve who could already read the file.
func sealTo(keyPath, rulePath, target string, recipients []string, plain string) ([]byte, error) {
	return runSops(keyPath, rulePath, "--encrypt",
		"--age", strings.Join(recipients, ","),
		"--filename-override", target, plain)
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// chownLike gives the replacement the original's owner and group, so an edit
// does not hand the secrets directory back to root.
func chownLike(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner of the file being replaced")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

// removeOnSignal removes dir when a terminating signal arrives, and returns the
// function that uninstalls the handler. A deferred cleanup does not run when
// the process does not return, and what is left behind is the whole decrypted
// store, on a tmpfs that keeps it until the machine reboots.
//
// SIGHUP is the one that happens: closing the terminal while the editor is
// open. The signal is re-raised with its default disposition afterwards, so
// the caller still sees a process killed by a signal.
func removeOnSignal(dir string) func() {
	signals := make(chan os.Signal, 1)
	signal.Notify(signals, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		received, ok := <-signals
		if !ok { // uninstalled: the caller returned normally and its defer cleans up
			return
		}
		_ = os.RemoveAll(dir)
		signal.Stop(signals)
		if sig, ok := received.(syscall.Signal); ok {
			signal.Reset(sig)
			_ = syscall.Kill(os.Getpid(), sig)
		}
	}()
	return func() {
		// Stop before close, so nothing can be sent to a closed channel.
		signal.Stop(signals)
		close(signals)
	}
}
