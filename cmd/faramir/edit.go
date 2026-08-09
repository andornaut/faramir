package main

// `faramir edit` is how a managed sops file is changed once the store belongs
// to the store group and the operator is not in it.
//
// It does not go through the broker or the keeper.  The keeper serves values
// and fingerprints and has no operation that returns key material, and adding
// one would defeat the reason it is a separate service.  Under sudo this
// process is already root,
// which can read the age key directly, so mediating the edit would add a
// protocol surface without moving a boundary.
//
// What it does buy, over running sops by hand:
//
//   - The plaintext never exists under the operator's uid.  A coding agent runs
//     as the operator, so a temporary file readable by that uid is readable by
//     the agent; here it is 0600 root in a tmpfs.
//   - The editor is a path this process chose, never one the environment named.
//     $EDITOR, $VISUAL and $SUDO_EDITOR are all writable by anything running as
//     the operator, including through a shell rc file, so honouring one would
//     let that account choose what runs as root.
//   - Only a file the config already manages can be opened, so a path argument
//     cannot walk somewhere else.
//   - The edit is recorded, which a bare sops invocation is not.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
)

// sopsBinary is resolved through PATH like any other command.  A variable so a
// test can point it at a build of its own rather than at whatever the host has
// installed.
var sopsBinary = "sops"

// editors are tried in order when none is given.  Absolute paths to real
// editors: "sensible-editor" and "editor" are deliberately absent because both
// resolve through files the operator can write, which is the thing this avoids.
var editors = []string{
	"/usr/bin/nano",
	"/bin/nano",
	"/usr/bin/vim",
	"/usr/bin/vi",
	"/bin/vi",
}

func cmdEdit(args []string) int {
	fs := newFlagSet("edit", "edit a managed sops file")
	configPath := fs.String("config", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	editor := fs.String("editor", "", "absolute path to the editor to run (default: the first of "+
		strings.Join(editors, ", ")+" that exists)")
	ageKey := fs.String("age-key", "", "age key file (default: age.key beside the config)")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}
	if fs.NArg() != 1 {
		fmt.Fprintln(os.Stderr, "usage: faramir edit [options] FILE")
		return 2
	}

	// Refused rather than attempted: as the operator this would fail on the age
	// key with a bare permission error, and the fix is not obvious from it.
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir edit must run as root, because the age key is "+
			"readable only by the keeper and by root: try 'sudo faramir edit'")
		return 1
	}

	cfg, err := config.Load(resolveConfig(*configPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}

	// Expanded, because [secrets] files holds glob patterns and what can be
	// edited is the files they name.  This process is root, so it can read the
	// store directory; the broker cannot, which is why this does not ask it.
	//
	// The upshot is that a sops file dropped into the store is editable at once,
	// with no config to change first, the same way the keeper picks it up.
	managed, unresolvable := keeper.Resolve(cfg.Secrets.Files)
	target, err := resolveManaged(managed, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}

	editorPath, err := resolveEditor(*editor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	keyPath := *ageKey
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.Path), "age.key")
	}
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "age key: %v\n", err)
		return 1
	}

	changed, err := editManaged(target, keyPath, editorPath)
	record := map[string]any{
		"op":     "edit",
		"id":     audit.NewLogID(),
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
	// The record names the file and whether it changed, never what is in it.
	audit.NewLog(cfg.Audit).Write(record, "")

	if err != nil {
		fmt.Fprintf(os.Stderr, "edit: %v\n", err)
		return 1
	}
	if !changed {
		fmt.Fprintln(os.Stderr, "unchanged")
		return 0
	}
	fmt.Fprintf(os.Stderr, "wrote %s; the broker picks it up within one refresh interval\n", target)
	return 0
}

// brokerUnit records the config the daemons actually loaded.  A variable so a
// test can point it at a fixture rather than at this host's systemd.
var brokerUnit = "/etc/systemd/system/faramir-broker.service"

// resolveConfig finds the config this edit has to agree with.
//
// An explicit --config wins, then $FARAMIR_CONFIG, then the compiled default,
// and only then the broker's unit.  That last step is what makes the command
// usable under sudo on an install that moved its config into a home: sudo
// clears the environment, so the variable the daemons are given does not
// survive to here, and the compiled default names a file that does not exist.
// Editing the wrong store, or reporting that there is none, are both worse than
// reading one line out of the unit that says which one is live.
func resolveConfig(requested string) string {
	if requested != "" || os.Getenv("FARAMIR_CONFIG") != "" {
		return requested
	}
	// Asked of the running broker, the same way the other provisioning commands
	// ask it, so there is one answer to "which config is live" rather than two.
	if path := filepath.Join(resolveConfigDir("", socketDefault()), "config.toml"); exists(path) {
		return path
	}
	// The broker checks a caller against [server] allowed_groups, and under sudo
	// this process is root, which is not in that group: the question above can
	// go unanswered precisely when this command is the one asking.  The unit is
	// the same answer written down, and it is readable by the uid that got here.
	body, err := os.ReadFile(brokerUnit)
	if err != nil {
		return ""
	}
	for _, line := range strings.Split(string(body), "\n") {
		if rest, found := strings.CutPrefix(strings.TrimSpace(line),
			"Environment=FARAMIR_CONFIG="); found {
			return rest
		}
	}
	return ""
}

func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// resolveManaged maps the argument onto one of the configured files.  A bare
// name is matched against each base name so that the common case does not need
// the whole path, and anything that is not managed is refused: the config is
// what says which files exist, and an edit outside that list would write a file
// the broker never reads.
func resolveManaged(managed []string, arg string) (string, error) {
	if len(managed) == 0 {
		return "", errors.New("no managed sops files: [secrets] files named none, " +
			"so there is nothing to edit. Create the first one with sops, which " +
			"needs --config and --filename-override; see docs/ansible-sops.md")
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
		return "", fmt.Errorf("%s is not a managed file; [secrets] files names %s",
			arg, strings.Join(managed, ", "))
	default:
		return "", fmt.Errorf("%s matches more than one managed file (%s); name the full path",
			arg, strings.Join(matches, ", "))
	}
}

// resolveEditor takes the requested editor or the first candidate that exists.
// An absolute path either way, so that what runs as root does not depend on
// PATH, which is inherited from whoever invoked sudo.
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
	return "", fmt.Errorf("no editor found; install one of %s or pass -editor",
		strings.Join(editors, ", "))
}

// unsafeToRunAsRoot names why this file must not be the editor, or "" if it may
// be.
//
// The editor runs as root with the decrypted store open, so a file the operator
// can write is the operator choosing what runs as root, which is the thing
// picking the editor here rather than from $EDITOR was for.  An account that can
// already write /usr/bin has that anyway; what this refuses is the ordinary
// case, a build in a home or a script in a group-writable directory.
//
// The directory holding it counts as much as the file: write there is
// permission to unlink what is on the path and put something else in its place.
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
// whether the plaintext changed.
//
// sops is run twice rather than with its own `sops FILE` editing mode, because
// that mode picks the editor out of the environment.  Decrypting and encrypting
// as separate steps is what lets the editor be chosen here instead.
func editManaged(target, keyPath, editorPath string) (bool, error) {
	// A tmpfs, so the plaintext is never written to a disk.  MkdirTemp creates
	// it 0700, which is what keeps every other uid out of the plaintext while
	// the editor has it open, and the umask can only make that stricter.
	dir, err := os.MkdirTemp("/dev/shm", "faramir-edit-")
	if err != nil {
		return false, fmt.Errorf("temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name, not a generic one.  Creation rules in .sops.yaml
	// select by path_regex, and the shipped rule ends in \.sops\.ya?ml$: a
	// temporary file called anything else matches no rule and encrypts to no
	// recipient at all.
	plain := filepath.Join(dir, filepath.Base(target))

	decrypted, err := runSops(keyPath, "--decrypt", target)
	if err != nil {
		return false, fmt.Errorf("decrypt %s: %w", target, err)
	}
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return false, err
	}

	cmd := exec.Command(editorPath, plain)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	// The editor gets a fixed environment.  It runs as root, and every variable
	// an editor reads for configuration is one the operator can set.
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

	// Re-encrypted to the recipients the file already had, named explicitly.
	//
	// Two reasons not to let sops find them itself.  It resolves .sops.yaml by
	// walking up from the file being encrypted, and this one is in a tmpfs, so
	// it would walk out of /dev/shm and match no creation rule.  And an edit
	// should preserve who could read the file, which is what sops' own edit
	// mode does: applying a changed .sops.yaml is what `sops updatekeys` is
	// for, and doing it silently here could drop a reader mid-edit.
	recipients, err := recipientsOf(target)
	if err != nil {
		return false, err
	}
	reencrypted, err := runSops(keyPath, "--encrypt", "--age", strings.Join(recipients, ","), plain)
	if err != nil {
		return false, fmt.Errorf("encrypt: %w", err)
	}
	return true, writeBack(target, reencrypted)
}

// writeBack replaces the managed file without changing who owns it.  Written
// beside the target and renamed, so a failure part way through cannot leave a
// truncated store that decrypts for nobody.
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
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Chmod(tmp.Name(), info.Mode().Perm()); err != nil {
		return err
	}
	if err := chownLike(tmp.Name(), info); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), target)
}

// runSops execs sops with the key supplied as a path.  The key reaches sops the
// same way the keeper supplies it, as SOPS_AGE_KEY_FILE, so it is absent from
// the environment block of anything that could be read from /proc.
//
// A fixed environment, like the editor's and like the keeper's: this runs as
// root, and sops reads several variables that name a key or a key source
// (SOPS_AGE_KEY among them).  Inheriting them would let the account that
// invoked sudo choose what the decryption uses.
func runSops(keyPath string, args ...string) ([]byte, error) {
	cmd := exec.Command(sopsBinary, args...)
	cmd.Env = []string{
		"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
		"HOME=" + envOr("HOME", "/tmp"),
		"LANG=C.UTF-8",
		"SOPS_AGE_KEY_FILE=" + keyPath,
	}
	cmd.Stderr = os.Stderr
	return cmd.Output()
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// chownLike gives the replacement the owner and group the original had, so a
// store handed to the store group by an install is not quietly handed back to
// root by an edit.
func chownLike(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner of the file being replaced")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

// ageRecipient matches the recipient entries in a sops metadata block, in both
// the YAML and the JSON encodings.  The metadata is cleartext, so this reads
// nothing secret and needs no key.
var ageRecipient = regexp.MustCompile(`recipient"?\s*:\s*"?(age1[0-9a-z]+)`)

// recipientsOf reads the age recipients a managed file is already encrypted to.
//
// Parsed with a regex rather than a YAML library on purpose: the sops libraries
// are kept out of these binaries deliberately, and pulling in a parser for one
// cleartext field would undo that for no benefit.
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
