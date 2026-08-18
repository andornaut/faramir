package main

// `faramir edit` changes a managed sops file once the secrets directory belongs
// to the secrets group and the operator does not.  It runs sops itself rather
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
	"regexp"
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

// sopsBinary is resolved through PATH.  A variable so a test can point it
// elsewhere.
var sopsBinary = "sops"

// editors are tried in order when none is given.  Absolute paths only:
// "sensible-editor" and "editor" resolve through files the operator can write.
var editors = []string{
	"/usr/bin/nano",
	"/bin/nano",
	"/usr/bin/vim",
	"/usr/bin/vi",
	"/bin/vi",
}

type editFlags struct {
	configPath string
	editor     string
	ageKey     string
	socket     string
}

func newEditCmd() *cobra.Command {
	var f editFlags
	c := &cobra.Command{
		Use:   "edit [options] FILE",
		Short: "edit a managed sops file",
		Args:  exactlyOneArg("file"),
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runEdit(f, args)) },
	}
	c.Flags().StringVarP(&f.configPath, "config", "c", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	c.Flags().StringVar(&f.editor, "editor", "", "absolute path to the editor to run (default: the first of "+
		strings.Join(editors, ", ")+" that exists)")
	c.Flags().StringVar(&f.ageKey, "age-key", "", "age key file (default: age.key beside the config)")
	c.Flags().StringVar(&f.socket, "socket", socketDefault(), "broker socket to ask where the install is ($FARAMIR_SOCKET)")
	return c
}

func runEdit(f editFlags, args []string) int {

	// Refused rather than attempted: the bare permission error on the age key does
	// not say what to do.
	if !requireRoot("edit", "the age key is readable only by the keeper and by root") {
		return 1
	}

	cfg, err := config.Load(resolveConfig(f.configPath, f.socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir edit: %v\n", err)
		return 1
	}

	// Expanded here, since the managed store holds globs and this process is root
	// where the broker cannot read the secrets directory.  So a sops
	// file dropped into the secrets directory is editable at once.
	// Both kinds together: this is a diagnostic printed when the named file is
	// not among the managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	unresolvable := slices.Concat(failures, absent)
	target, err := resolveManaged(managed, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir edit: %v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}

	editorPath, err := resolveEditor(f.editor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir edit: %v\n", err)
		return 1
	}

	keyPath := f.ageKey
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.Path), "age.key")
	}
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir edit: age key: %v\n", err)
		return 1
	}

	// The install's own rules, named rather than left to sops to find: see
	// runSops.  Beside the config like the age key, and the same file `rekey`
	// reads, so an edit and a rekey on one host agree about what governs a
	// managed file.
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")

	changed, err := editManaged(keyPath, rulePath, editorPath, target)
	record := map[string]any{
		"op": opEdit,
		// "log_id", the spelling the broker writes and the only one `faramir logs`
		// reads: under any other key the record has no id to look up and no timestamp
		// to sort by, both of which it derives from this one.
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
		fmt.Fprintf(os.Stderr, "faramir edit: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "faramir edit: unchanged")
		return 0
	}
	fmt.Fprintf(os.Stderr, "faramir edit: wrote %s; the broker picks it up within one refresh interval\n", target)
	return 0
}

// resolveConfig finds the config a client command has to agree with: --config,
// then $FARAMIR_CONFIG, then whatever discoverConfigFile finds, then the
// compiled default if it is there.
//
// An explicit $FARAMIR_CONFIG returns empty like the rest: the variable is
// config.Load's to read, so returning a path here would override the caller's
// own choice.
//
// Reaching the unit matters under sudo on an install whose config moved into a
// home: sudo clears the environment, and the socket goes unanswered whenever
// the broker is not running.
func resolveConfig(requested, socketPath string) string {
	if requested != "" || os.Getenv("FARAMIR_CONFIG") != "" {
		return requested
	}
	return installedConfig(discoverConfigFile(askBroker(socketPath)))
}

// resolveDaemonConfig is resolveConfig for the three daemon entry points, which
// under systemd are given no -c at all: the unit sets FARAMIR_CONFIG instead.
// Run by hand with neither, the install still has to be found rather than
// assumed, `faramir broker --check` being the invocation that reaches this.
//
// The running broker is not a step here, unlike resolveConfig: this process may
// be about to bind the broker's own socket, and connecting to it would
// socket-activate the installed daemon and leave the two contending for the
// path.  The unit answers the same question without the round trip, being where
// a running broker's config came from.
func resolveDaemonConfig(requested string) string {
	if requested != "" || os.Getenv("FARAMIR_CONFIG") != "" {
		return requested
	}
	return installedConfig(unitConfigFile())
}

// installedConfig takes what discovery found, and falls back to the compiled-in
// default only when that file is there.  An empty result is deferred to
// config.Load rather than guessed at: Load names the default itself, and the
// error it reports for a host with no install is the one to print.
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

// errNoManagedFiles is what edit and rekey both report when the secrets
// directory is empty: neither has anything to open, and the fix is the same for
// both.
var errNoManagedFiles = errors.New("no managed sops files: the managed store named " +
	"none, so there is nothing to open. Create the first one with sops, which " +
	"needs --config and --filename-override; see docs/ansible-sops.md")

// resolveManaged maps the argument onto one of the configured files, matching a
// bare name against each base name.  Anything unmanaged is refused, an edit
// outside the list being a file the broker never reads.
func resolveManaged(managed []string, arg string) (string, error) {
	if len(managed) == 0 {
		return "", errNoManagedFiles
	}
	var matches []string
	wanted := filepath.Clean(arg)
	for _, file := range managed {
		if filepath.Clean(file) == wanted || filepath.Base(file) == arg {
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
// be.  The editor runs as root with the decrypted store open, so a file the
// operator can write is the operator choosing what runs as root.  The directory
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
// whether the plaintext changed.  Two sops runs rather than its own `sops FILE`
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

	// The recipients the file already had, named explicitly: sops resolves
	// .sops.yaml by walking up from the file, which here is in a tmpfs, and an
	// edit should preserve who could read the file; applying a changed .sops.yaml
	// is what `faramir rekey` is for.
	//
	// Read before the editor runs.  It is knowable from the ciphertext, and a
	// file whose metadata this cannot parse would otherwise be reported only
	// after the operator had already made their edit, which is then discarded.
	recipients, err := recipientsOf(target)
	if err != nil {
		return false, err
	}

	// Asked here, beside the recipients, and for the same reason: sops refuses a
	// file no creation rule covers, and it refuses it at the encrypt, which is
	// after the editor has run.  Learning then costs the operator everything they
	// typed, so the question is put while there is nothing to lose.
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
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"TERM=" + os.Getenv("TERM"), "LANG=C.UTF-8", "HOME=" + dir}
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
		// Said plainly, because the plaintext is about to go with the tmpfs
		// directory and the operator's typing goes with it.  Keeping it would be
		// leaving a decrypted store on a machine after a command that failed.
		return false, fmt.Errorf("encrypt: %w. The edit was not saved and the "+
			"decrypted copy has been removed, so make it again once this is fixed", err)
	}
	return true, writeBack(target, reencrypted)
}

// writeBack replaces the managed file without changing who owns it, written
// beside the target and renamed so a partial failure leaves no truncated store.
//
// Both halves are made durable before this returns, which is not ceremony here:
// this is the one operation in faramir that overwrites the only copy of the
// secrets on the host, and `rekey` performs it once per managed file.  The
// contents are flushed before the rename, or a crash can leave the new name
// pointing at a file whose data never landed and whose predecessor is gone; the
// directory is flushed after it, or the rename itself is what is missing.
//
// The mode before the owner: the temporary file is created 0600 and root's, so
// widening it while it is still root:root gives nothing away, where chowning
// first would hand it over at whatever mode it happened to have.
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
	// Reported and not returned.  By here the replacement is the file: what failed
	// is the promise that it survives a power loss, not the write.  Returning an
	// error would tell the operator their edit did not take, sending them to make
	// it again over content that has already changed, and would have `rekey` count
	// the file among those "still open to the recipients they had", which is the
	// one thing that is certainly false about it.
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
// supplies it, so it is absent from any environment block in /proc.  A fixed
// environment, since sops reads several variables naming a key or key source.
//
// --config names the creation rules, and naming them is what keeps them this
// host's own.  Left to search, sops resolves .sops.yaml by walking up from the
// process's working directory, which here is wherever the operator was standing
// when they typed the command, and that is very often an enrolled working tree
// the coding agent writes.  A .sops.yaml found there governs the encryption:
// `unencrypted_regex` and `unencrypted_suffix` make sops write the values they
// name in cleartext into the managed file.  Recipients are safe either way, the
// --age on the command line winning over anything a rule lists, but the shape of
// the file is not.
//
// The flag rather than the SOPS_CONFIG variable that does the same thing: the
// variable is the newer of the two, and a sops old enough not to know it ignores
// it and searches anyway -- which is this guard silently absent rather than
// failing.  An argument sops does not understand is an error instead.
func runSops(keyPath, rulePath string, args ...string) ([]byte, error) {
	argv := append([]string{"--config", sopsConfigPath(rulePath)}, args...)
	cmd := exec.CommandContext(context.Background(), sopsBinary, argv...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + envOr("HOME", "/tmp"),
		"LANG=C.UTF-8",
		"SOPS_AGE_KEY_FILE=" + keyPath,
	}
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// sopsConfigPath is the creation rules to hand sops, and /dev/null where there
// are none to hand it.
//
// A rule file that is not there is not the same as none: sops refuses to start
// on a --config it cannot read, decrypt included, so naming an absent path would
// take away the ability to open a file rather than the ability to search for a
// rule.  /dev/null parses as a document with no creation rules, which is what a
// host without one has.
func sopsConfigPath(rulePath string) string {
	if rulePath != "" && exists(rulePath) {
		return rulePath
	}
	return os.DevNull
}

// ruleMustCover refuses an edit the creation rules cannot write back, or nil.
//
// A host with no rule at all encrypts with sops' defaults, which covers every
// file, so there is nothing to ask there: sopsConfigPath has already turned that
// into /dev/null and this returns at once.
//
// A probe that cannot be put is not a refusal.  What is being ruled out is the
// one case that is certain to fail later, and refusing an edit because sops
// could not be run would take away a command over a question nobody needed
// answered.
func ruleMustCover(rulePath, target string, recipients []string) error {
	configPath := sopsConfigPath(rulePath)
	if configPath == os.DevNull {
		return nil
	}
	if err := ruleMustNotSplitTheKey(rulePath); err != nil {
		return err
	}
	// Covered unless the probe says otherwise, which is what makes an unputtable
	// probe leave the edit alone.
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
// or nil.
//
// The refusal `faramir rekey` already makes, made here for the same reason and
// one step earlier.  shamir_threshold means N of the rule's key groups have to
// come together to open a file; what an edit writes back is sealed to the
// recipients the file already carried, as one group.  sops takes that without
// complaint and writes the threshold beside the single group, so the file still
// opens -- with any one of those keys, which is what the rule was written to
// prevent.  A protection removed by a command nobody asked to remove it is worse
// than an edit that will not run.
//
// A rule this cannot read is not a refusal: the same rule reaches sops next, and
// what it says about it is the answer the operator should see.
func ruleMustNotSplitTheKey(rulePath string) error {
	// A rule this cannot read leaves rules empty and nothing to refuse, which is
	// the intent: the same file reaches sops next, and what sops says about it is
	// the answer the operator should be given.
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
// against the path of the file it is handed taken relative to the rule file, and
// what it is handed here is the copy in the tmpfs: nowhere near the rule, so the
// absolute tmpfs path is what a rule would be judged against, and one naming
// where the secrets live matches nothing.  Every edit would end in "no matching
// creation rules found".  With the override the rule sees what it sees under
// ordinary use, which on an install is `secrets/<name>`.
//
// The recipients are named here rather than taken from the rule, which is what
// makes an edit preserve who could already read the file: applying a changed
// rule is `faramir rekey`.
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
// function that uninstalls the handler.  A deferred cleanup does not run when
// the process does not return, and what is left behind here is the whole
// decrypted store, on a tmpfs that keeps it until the machine reboots.
//
// SIGHUP is the one that happens: closing the terminal while the editor is
// open.  The signal is re-raised with its default disposition afterwards, so
// the caller still sees a process killed by a signal rather than an exit code
// invented here.  Every signal caught here would have terminated the process
// anyway, so nothing survives that did not before.
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

// ageRecipient matches the recipient entries in a sops metadata block, in every
// encoding: "recipient: age1..." in YAML, "recipient": "age1..." in JSON, and
// sops_age__list_0__map_recipient=age1... in the dotenv and ini forms.  The
// metadata is cleartext, so this needs no key.
var ageRecipient = regexp.MustCompile(`recipient"?\s*[:=]\s*"?(age1[0-9a-z]+)`)

// recipientsOf reads the age recipients a managed file is already encrypted to.
// A regex rather than a YAML library, which would undo keeping the sops
// libraries out of this binary for one cleartext field.
func recipientsOf(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	seen := map[string]bool{}
	for _, match := range ageRecipient.FindAllSubmatch(body, -1) {
		recipient := string(match[1])
		if !seen[recipient] {
			seen[recipient] = true
			out = append(out, recipient)
		}
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no age recipient, so there is nothing to "+
			"re-encrypt it to; faramir manages age-encrypted files only", path)
	}
	return out, nil
}
