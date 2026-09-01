// Package vault is the managed secret store: the sops-encrypted files under the
// config directory, and the operations that create, edit and re-seal one.
//
// It execs sops rather than linking it, which is what keeps every cloud KMS SDK
// out of the shipped binary, and it never decrypts to a path an agent could
// read: an edit goes to a private temp directory that is removed on a signal as
// well as on a return.
//
// Three rules the callers rest on:
//
//   - A file is written back only if it has not changed since it was read.
//     Two editors on one file would otherwise leave one of them silently gone.
//   - The creation rule has to cover the file before it is sealed, and must not
//     be split across a bare `age:` beside key groups. A rule that covers
//     nothing seals to nobody, and looks exactly like one that covers
//     everything.
//   - The keeper stays a reader. A re-seal that dropped it would leave a store
//     the broker can no longer open, and nothing else would have said so.
//
// It prints nothing and exits nothing: the commands in cmd/faramir report what
// it returns.
package vault

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"unicode/utf8"

	yaml "go.yaml.in/yaml/v3"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
	"github.com/andornaut/faramir/internal/termsafe"
)

// The environment a child editor is started with. A fixed PATH so the editor
// found is one on the system's own, and a UTF-8 locale so a value carrying
// anything but ASCII survives the round trip through it.
const (
	envPATH = "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
	envLANG = "LANG=C.UTF-8"
)

// SopsBinary is resolved through PATH. A variable so a test can point it
// elsewhere.
var SopsBinary = "sops"

// Editors are tried in order when none is given. Absolute paths only:
// "sensible-editor" and "editor" resolve through files the operator can write.
var Editors = []string{
	"/usr/bin/vim",
	"/usr/bin/vi",
	"/bin/vi",
	"/usr/bin/nano",
	"/bin/nano",
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

// Resolve maps the argument onto one of the configured files, matching a
// bare name against each base name and against each name without its suffix.
// Anything unmanaged is refused, an edit outside the list being a file the
// broker never reads.
func Resolve(managed []string, arg string) (string, error) {
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

// ResolveEditor picks the editor and holds every source to the same check. In
// order: --editor, $VISUAL, $EDITOR, then the first of editors that passes.
//
// The variables are read because the check, not the source, is what makes a
// program safe to run as root over the decrypted store: an account that cannot
// write the binary or any directory above it cannot change what runs, cannot
// pass it an argument, and cannot reach it through a config file either, the
// child's HOME being the tmpfs. Under plain sudo env_reset drops both
// variables, so on a stock host the built-in list is what decides.
func ResolveEditor(requested string) (string, error) {
	for _, source := range []struct{ named, value string }{
		{"--editor", requested},
		{"$VISUAL", os.Getenv("VISUAL")},
		{"$EDITOR", os.Getenv("EDITOR")},
	} {
		if source.value == "" {
			continue
		}
		// Refused rather than passed over: a named editor that cannot be run is
		// the operator's own setting, and falling through to the list would open
		// the store in an editor they did not ask for and say nothing about it.
		path, err := CheckedEditor(source.value)
		if err != nil {
			return "", fmt.Errorf("%s %w", source.named, err)
		}
		return path, nil
	}
	// The list is held to the check too. A candidate that is simply not installed
	// is not worth reporting; one that is there and cannot be run is the whole
	// answer to "no editor found".
	var refused []string
	for _, candidate := range Editors {
		path, err := CheckedEditor(candidate)
		if err == nil {
			return path, nil
		}
		if !errors.Is(err, os.ErrNotExist) {
			refused = append(refused, err.Error())
		}
	}
	if len(refused) > 0 {
		return "", fmt.Errorf("no editor here can be run as root: %s",
			strings.Join(refused, "; "))
	}
	return "", fmt.Errorf("no editor found; install one of %s, or name one with "+
		"--editor, $VISUAL or $EDITOR", strings.Join(Editors, ", "))
}

// CheckedEditor resolves one candidate to the absolute path that will be
// exec'd, or says why it cannot be.
//
// Symlinks are resolved first and the resolved path is what runs. Checking one
// path and exec'ing another would leave the links in between deciding it:
// /usr/bin/vi is an alternatives symlink on a Debian host, and the file it
// names is not the one an ownership check of /usr/bin/vi reads.
func CheckedEditor(named string) (string, error) {
	// A bare path, never a command line. "vim -u /somewhere/vimrc" is an ordinary
	// thing to have in $EDITOR, and -u names a file of commands vim runs on
	// startup: passing arguments through would let an account that owns that file
	// choose what root does while every ownership check still passed. A path
	// holding a space is refused with it, which is the safe direction.
	if len(strings.Fields(named)) > 1 {
		return "", fmt.Errorf("%q names arguments, and faramir runs the program "+
			"alone: give the path by itself", named)
	}
	// Absolute, so what runs as root does not depend on an inherited PATH.
	if !filepath.IsAbs(named) {
		return "", fmt.Errorf("%q must be an absolute path", named)
	}
	resolved, err := filepath.EvalSymlinks(named)
	if err != nil {
		return "", fserr.At(named, err)
	}
	info, err := os.Stat(resolved)
	if err != nil {
		return "", fserr.At(resolved, err)
	}
	if reason := UnsafeToRunAsRoot(resolved, info); reason != "" {
		return "", fmt.Errorf("%s: %s", resolved, reason)
	}
	return resolved, nil
}

// UnsafeToRunAsRoot names why this file must not be the editor, or "" if it may
// be. The editor runs as root with the decrypted store open, so a file an
// account other than root can write is that account choosing what runs as root.
//
// Every directory above it counts as much as the file: write on a directory is
// permission to replace what it holds, and write on that directory's parent is
// permission to replace the directory. So the walk runs to /. The path is
// expected to be resolved already, which is what makes stat'ing each ancestor
// the same question the kernel will answer at exec.
func UnsafeToRunAsRoot(path string, info os.FileInfo) string {
	if !info.Mode().IsRegular() {
		return "not a regular file"
	}
	for at := path; ; at = filepath.Dir(at) {
		stat, ok := mustStat(at)
		if !ok {
			return "cannot read the owner of " + at
		}
		if stat.Uid != 0 {
			return fmt.Sprintf("%s belongs to uid %d rather than root, which is the "+
				"account that would then choose what runs as root", at, stat.Uid)
		}
		// Group and other: root owning it is the point, so its own write bit is
		// not a finding. A sticky directory lets only an entry's owner remove it
		// and would be safe, but no editor lives in one and refusing costs
		// nothing.
		if mode := os.FileMode(stat.Mode).Perm(); mode&0o022 != 0 {
			return fmt.Sprintf("%s is %04o: an account that is not root can replace "+
				"what runs here", at, mode)
		}
		if parent := filepath.Dir(at); parent == at {
			return ""
		}
	}
}

func mustStat(path string) (*syscall.Stat_t, bool) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, false
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	return stat, ok
}

// Edit decrypts, edits and re-encrypts one file in place, and reports
// whether the plaintext changed. Two sops runs rather than its own `sops FILE`
// mode, which picks the editor out of the environment.
func Edit(keyPath, rulePath, editorPath, target string) (bool, error) {
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
	if err := RuleMustCover(rulePath, target, recipients); err != nil {
		return false, err
	}

	// The ciphertext as it stands now, compared again before the write. Two edits
	// of one file each decrypt their own copy, and whichever encrypts last would
	// otherwise replace the other's work with a copy that never had it, both
	// having reported the file written.
	before, err := DigestOf(target)
	if err != nil {
		return false, err
	}

	decrypted, err := RunSops(keyPath, rulePath, "--decrypt", target)
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
	if err := UnchangedSince(target, before); err != nil {
		return false, err
	}
	return true, WriteBack(target, reencrypted)
}

// DigestOf is the file's contents hashed, which is what says whether it is the
// one this started from.
func DigestOf(path string) ([]byte, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(body)
	return sum[:], nil
}

// UnchangedSince refuses a write onto a file something else has written since
// this read it. The edit is lost either way; what this decides is whose.
func UnchangedSince(path string, before []byte) error {
	now, err := DigestOf(path)
	if err != nil {
		return err
	}
	if !bytes.Equal(now, before) {
		return fmt.Errorf("%s changed while this was working on it, so nothing was "+
			"written: another `faramir vault edit`, `reader` or `reseal`, or something "+
			"writing the file directly, got there first. Run this again", path)
	}
	return nil
}

// WriteBack replaces the managed file without changing who owns it, written
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
func WriteBack(target string, data []byte) error {
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

// RunSops execs sops with the key as a path (SOPS_AGE_KEY_FILE), as the keeper
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
func RunSops(keyPath, rulePath string, args ...string) ([]byte, error) {
	argv := append([]string{"--config", SopsConfigPath(rulePath)}, args...)
	cmd := exec.CommandContext(context.Background(), SopsBinary, argv...)
	cmd.Env = []string{
		envPATH,
		"HOME=" + envOr("HOME", "/tmp"),
		envLANG,
		"SOPS_AGE_KEY_FILE=" + keyPath,
	}
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

// SopsConfigPath is the creation rules to hand sops, and /dev/null where there
// are none. A rule file that is not there is not the same as none: sops
// refuses to start on a --config it cannot read, decrypt included, where
// /dev/null parses as a document with no creation rules.
func SopsConfigPath(rulePath string) string {
	if rulePath != "" && exists(rulePath) {
		return rulePath
	}
	return os.DevNull
}

// RuleMustCover refuses an edit the creation rules cannot write back, or nil.
// A host with no rule encrypts with sops' defaults, which cover every file, and
// sopsConfigPath has already turned that into /dev/null.
//
// A probe that cannot be put is not a refusal: what is ruled out is the case
// certain to fail later.
func RuleMustCover(rulePath, target string, recipients []string) error {
	configPath := SopsConfigPath(rulePath)
	if configPath == os.DevNull {
		return nil
	}
	if err := ruleMustNotSplitTheKey(rulePath); err != nil {
		return err
	}
	// Covered unless the probe says otherwise, which is what makes a probe that
	// cannot be put leave the edit alone.
	covered := true
	if sops, err := exec.LookPath(SopsBinary); err == nil {
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
// or nil. The refusal `faramir reader reseal` makes, one step earlier:
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
	return RunSops(keyPath, rulePath, "--encrypt",
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

// NewManagedPath is where a new file goes, or why it may not go there.
// Relative to the secrets directory, which is the only place the broker reads,
// and checked against the patterns rather than the directory alone: a name the
// globs do not match encrypts perfectly well and is then served to nobody.
func NewManagedPath(cfg *config.Config, name string) (string, error) {
	if len(cfg.Secret.Patterns) == 0 {
		return "", errors.New("[secret] patterns names no location for a managed file")
	}
	dir := filepath.Dir(cfg.Secret.Patterns[0])
	// Asked before a path is built out of it: Join drops an empty name and a
	// ".", so both would be answered about the secrets directory with a suffix
	// glued on, which is a path the operator never typed and cannot correct.
	if strings.TrimSpace(name) == "" || filepath.Clean(name) == "." {
		return "", fmt.Errorf("name the file to create: a name relative to %s, "+
			"which is where a managed file lives", dir)
	}
	if err := refuseUnprintable(name); err != nil {
		return "", err
	}
	target := name
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	target = filepath.Clean(target)

	// The suffix is faramir's, not the operator's: they pick a name and this
	// writes a YAML store. A name that already carries a managed suffix is taken
	// as it stands, so naming a file in full is neither wrong nor doubled: the
	// refusal below then names what was typed, which is what the operator has to
	// correct.
	if !matchesPatterns(cfg.Secret.Patterns, target) && !carriesManagedSuffix(target) {
		target += managedSuffix
	}
	if !matchesPatterns(cfg.Secret.Patterns, target) {
		// The patterns in full, not their file names: a pattern shown as
		// "*.sops.yml" is one /tmp/outside.sops.yml plainly matches, and what it
		// misses is the directory the glob names.
		return "", fmt.Errorf("%s matches none of the [secret] patterns (%s), so the "+
			"broker would never read it and nothing in it could be named as a ref",
			target, joinPatterns(cfg.Secret.Patterns))
	}
	if exists(target) {
		return "", fmt.Errorf("%s is already there; `faramir vault edit %s` opens it",
			target, filepath.Base(target))
	}
	// Named rather than left to the write to fail on: a missing directory here
	// means an install that has not been run.
	if !exists(dir) {
		return "", fmt.Errorf("%s is not there, so there is nowhere to put a managed "+
			"file: `sudo faramir init` creates it", dir)
	}
	return target, nil
}

// refuseUnprintable holds a managed file's name to bytes that can be shown and
// typed. The same check a [[secret.block]] entry gets, for a different reason:
// a name is not a rule, so a newline splits nothing, but it is printed back by
// every command that touches the file and typed into every shell command that
// reaches it. Refused where it is written rather than escaped where it is
// shown, which would leave an operator with a file they cannot name.
//
// Decoded byte by byte rather than ranged over: ranging yields U+FFFD for a
// byte that is not valid UTF-8, which is not Actionable, so the check would
// not see it.
func refuseUnprintable(name string) error {
	for i := 0; i < len(name); {
		r, size := utf8.DecodeRuneInString(name[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("name %q carries a byte at offset %d that is not "+
				"valid UTF-8, so nothing can print the file's name back to you",
				config.Shown(name), i)
		}
		if termsafe.Actionable(r) {
			return fmt.Errorf("name %q carries %q at offset %d, which a terminal "+
				"acts on rather than draws", config.Shown(name), r, i)
		}
		i += size
	}
	return nil
}

// matchesPatterns reports whether the broker would read this path.
func matchesPatterns(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, target); ok {
			return true
		}
	}
	return false
}

// joinPatterns names the configured entries as a message quotes them: in full,
// each one being what a path is actually matched against.
func joinPatterns(patterns []string) string {
	out := append([]string{}, patterns...)
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// Add writes the new file, with the plaintext living only in a tmpfs.
// The same shape as an edit minus the decrypt, and the recipients come from the
// rule rather than from the file, which has none yet.
func Add(keyPath, rulePath, editorPath, from, target string) error {
	dir, err := os.MkdirTemp("/dev/shm", "faramir-add-")
	if err != nil {
		return fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
	plain := filepath.Join(dir, filepath.Base(target))

	recipients, err := RuleRecipients(rulePath)
	if err != nil {
		return err
	}
	// Asked before the editor opens, as an edit asks it: sops refuses a file no
	// creation rule covers at the encrypt, after everything has been typed.
	if err := RuleMustCover(rulePath, target, recipients); err != nil {
		return err
	}

	if err := fillPlaintext(editorPath, from, dir, plain); err != nil {
		return err
	}

	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return fmt.Errorf("encrypt: %w. Nothing was written and the decrypted copy "+
			"has been removed, so make it again once this is fixed", err)
	}
	return createManaged(target, sealed)
}

// fillPlaintext puts the content in the tmpfs, from a file or from an editor.
func fillPlaintext(editorPath, from, dir, plain string) error {
	if from != "" {
		body, err := os.ReadFile(from)
		if err != nil {
			return fserr.At(from, err)
		}
		if len(bytes.TrimSpace(body)) == 0 {
			return fmt.Errorf("%s holds nothing, and an encrypted file with nothing in "+
				"it names no ref", from)
		}
		return os.WriteFile(plain, body, 0o600)
	}
	if err := os.WriteFile(plain, nil, 0o600); err != nil {
		return err
	}
	cmd := exec.CommandContext(context.Background(), editorPath, plain)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// Fixed: the editor runs as root, and the operator can set every variable one
	// reads for configuration.
	cmd.Env = []string{envPATH,
		"TERM=" + os.Getenv("TERM"), envLANG, "HOME=" + dir}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("editor: %w", err)
	}
	body, err := os.ReadFile(plain)
	if err != nil {
		return err
	}
	// An empty file is how somebody says they changed their mind, and creating
	// one leaves a managed file naming no ref for the broker to serve.
	if len(bytes.TrimSpace(body)) == 0 {
		return errors.New("nothing was written, so no file was created")
	}
	return nil
}

// createManaged writes a file that was not there before, 0640 like every other
// managed one. The group comes from the secrets directory, which is setgid to
// the keeper's, so a new file is readable by the daemon that opens it without
// this naming an account. Written beside the target and renamed, and made
// durable, for the reasons writeBack does it.
func createManaged(target string, data []byte) error {
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
	// 0640 rather than tighter: the keeper's group has to open it. The same mode
	// every other managed file carries.
	if err := os.Chmod(tmp.Name(), 0o640); err != nil { //nolint:gosec // G302: the keeper's group reads the store
		return err
	}
	if err := os.Rename(tmp.Name(), target); err != nil {
		return err
	}
	if err := syncDir(filepath.Dir(target)); err != nil {
		fmt.Fprintf(os.Stderr, "faramir: %s was written, but %s could not be flushed "+
			"(%v), so it may not survive a power loss until something else syncs that "+
			"filesystem\n", target, filepath.Dir(target), err)
	}
	return nil
}

// AgeKeyPath is the key a run decrypts with: the install's own, beside its
// config, and no flag names another. A flag would name which key
// keeperStaysAReader checks, so a run pointed at a second identity could take
// the host's own key out of the rule and reseal the store without it, which no
// re-run undoes.
func AgeKeyPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path), "age.key")
}

// ResealTargets is every managed file, or just the ones named, which is for a
// secrets directory where one file is meant to stay as it is. Either way a
// path that is not managed is refused by resolveManaged, so a reseal cannot
// walk out of the secrets directory.
func ResealTargets(managed, named []string) ([]string, error) {
	if len(named) == 0 {
		if len(managed) == 0 {
			return nil, ErrNoFilesToReseal
		}
		return managed, nil
	}
	out := make([]string, 0, len(named))
	for _, arg := range named {
		target, err := Resolve(managed, arg)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, target) {
			out = append(out, target)
		}
	}
	return out, nil
}

// RuleRecipients reads who .sops.yaml says a managed file should be encrypted
// to. One creation rule only: the shipped file has exactly one, matching any
// *.sops.yml wherever it sits. With two the answer depends on which path_regex
// a file matches, which this cannot answer, so it refuses rather than
// re-encrypting half the secrets directory to the wrong set.
func RuleRecipients(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	return RuleRecipientsFrom(body, path)
}

// RuleRecipientsFrom is ruleRecipients for a caller holding the bytes, which is
// what a command that has edited the rule and not yet written it has: a rule
// this refuses is one the file should never come to hold.
func RuleRecipientsFrom(body []byte, path string) ([]string, error) {
	rules, err := sopsrule.Parse(body, path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	if len(rules) > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and which one governs a "+
			"file depends on its path_regex: re-key those with 'sops updatekeys' "+
			"per file, which is the only thing that can answer it", path, len(rules))
	}
	for _, rule := range rules {
		// A split data key is refused rather than flattened: shamir_threshold means
		// N key groups have to come together to open the file, and this re-encrypts
		// to one list of recipients, so any one of them would open what took N
		// before.
		if rule.ShamirThreshold > 0 {
			return nil, fmt.Errorf("%s sets shamir_threshold, so the data key is "+
				"split across key groups and %d of them are needed together: "+
				"re-encrypting here would seal it to one group holding every key, and "+
				"any one of them would open it. Re-key with 'sops updatekeys' per file",
				path, rule.ShamirThreshold)
		}
	}
	out := sopsrule.Recipients(rules)
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no age recipient, so there is nothing to "+
			"re-encrypt to; faramir manages age-encrypted files only", path)
	}
	return out, nil
}

// KeeperStaysAReader refuses a rule that leaves out the key this host decrypts
// with. The recipients are public keys, so the check is the public half of the
// age key against the list. Getting it wrong is not recoverable by re-running:
// the files would already be sealed to a set without the only identity on the
// host.
func KeeperStaysAReader(keyPath string, wanted []string, rulePath string) error {
	recipient, err := agekey.Recipient(keyPath)
	if err != nil {
		return fmt.Errorf("age key: %w", err)
	}
	if slices.Contains(wanted, recipient) {
		return nil
	}
	return fmt.Errorf("%s does not list %s, which is the key %s decrypts with: "+
		"re-encrypting to it would leave a secrets directory the keeper cannot open, and the "+
		"broker would come up serving nothing. Add it under '- age:' first",
		rulePath, recipient, keyPath)
}

// Reencrypt rewrites one managed file, sealed to the given recipients. The
// plaintext goes through a 0600 file in a tmpfs because sops encrypts a file
// and takes its name, which is what decides its format, so the copy keeps it.
// Which creation rule governs it is settled by --filename-override; see
// sealTo.
func Reencrypt(keyPath, rulePath string, recipients []string, target string) error {
	// The ciphertext as it stands now, compared again before the write: this
	// decrypts a copy of its own, and an edit that lands in between would be
	// replaced by one that never had it. See editManaged.
	before, err := DigestOf(target)
	if err != nil {
		return err
	}
	decrypted, err := RunSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	dir, err := os.MkdirTemp("/dev/shm", "faramir-reseal-")
	if err != nil {
		return fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	plain := filepath.Join(dir, filepath.Base(target))
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return err
	}
	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	if err := UnchangedSince(target, before); err != nil {
		return err
	}
	return WriteBack(target, sealed)
}

// ManagedFile is one file as `ls` reports it.
type ManagedFile struct {
	// Name is what an operator types, and Path is what is on disk. Both, so the
	// listing can be pasted into another command and read as a path.
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Refs       []string `json:"refs"`
	Recipients []string `json:"recipients"`
	// Drifted is true where the file is sealed to a set the rule no longer names,
	// which is what `faramir reader reseal` is for.
	Drifted bool `json:"drifted"`
	// Problem is why this file could not be read or parsed, and "" otherwise. A
	// file the broker would refuse is what an operator comes here to find, so it
	// is a row rather than a reason to stop.
	Problem string `json:"problem,omitempty"`
}

// StateOf is the one word a listing has room for.
func StateOf(file ManagedFile) string {
	switch {
	case file.Problem != "":
		return file.Problem
	case file.Drifted:
		return "drifted"
	}
	return "ok"
}

// DescribeManaged reads one file without decrypting it: both the ref names and
// the recipients are cleartext in a sops file.
func DescribeManaged(path string, wanted []string, haveRule bool) ManagedFile {
	file := ManagedFile{Name: managedStem(path), Path: path}
	recipients, err := sopsrule.SealedTo(path)
	if err != nil {
		file.Problem = "not sealed to any age recipient"
		return file
	}
	file.Recipients = recipients
	file.Drifted = haveRule && !sopsrule.Same(recipients, wanted)

	refs, err := RefsIn(path)
	if err != nil {
		file.Problem = err.Error()
		return file
	}
	file.Refs = refs
	return file
}

// RefsIn is the refs a managed file names, taken from its structure rather than
// its values. sops encrypts values and leaves keys readable, so this answers
// without the age key: [keeper.Flatten] is given the file as it sits on disk,
// so each ref maps onto ciphertext and only the names are kept.
func RefsIn(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	refs := make([]string, 0, len(doc))
	for ref := range keeper.Flatten(doc) {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	return refs, nil
}

// EditRule is the one call that differs between add and rm.
func EditRule(body []byte, path, recipient string, adding bool) ([]byte, bool, error) {
	if adding {
		return sopsrule.Add(body, path, recipient)
	}
	return sopsrule.Remove(body, path, recipient)
}

// ErrNoFilesToReseal is errNoManagedFiles said for this command: nothing to
// re-encrypt rather than nothing to open.
var ErrNoFilesToReseal = errors.New("no managed sops files: the managed store " +
	"named none, so there is nothing to re-encrypt. Write the first one with " +
	"`faramir vault add NAME`")
