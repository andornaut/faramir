package main

// `faramir edit` changes a managed sops file once the secrets directory belongs
// to the secrets group and the operator does not.  It runs sops itself rather
// than asking the keeper, which has no operation that returns key material;
// under sudo this process is already root.
//
// Over running sops by hand it buys: plaintext that is 0600 root in a tmpfs
// rather than readable by the uid the agent runs as; an editor this process
// chose, never one $EDITOR named; a path argument that cannot leave the managed
// set; and an audit record.

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
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

	// Refused rather than attempted: the bare permission error on the age key does
	// not say what to do.
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

	// Expanded here, since [secrets] files holds globs and this process is root
	// where the broker cannot read the secrets directory.  So a sops
	// file dropped into the secrets directory is editable at once.
	// Both kinds together: this is a diagnostic printed when the named file is
	// not among the managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secrets.Files)
	unresolvable := slices.Concat(failures, absent)
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
		"op": "edit",
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

// brokerUnit records the config the daemons loaded.  A variable so a test can
// point it at a fixture.
var brokerUnit = "/etc/systemd/system/faramir-broker.service"

// resolveConfig finds the config this edit has to agree with: --config, then
// $FARAMIR_CONFIG, then the compiled default, then the broker's unit.  The last
// step is what makes this work under sudo on an install whose config moved into
// a home, sudo having cleared the environment.
func resolveConfig(requested string) string {
	if requested != "" || os.Getenv("FARAMIR_CONFIG") != "" {
		return requested
	}
	// Asked of the running broker, as the other provisioning commands do.
	if path := filepath.Join(resolveConfigDir("", socketDefault()), "config.toml"); exists(path) {
		return path
	}
	// Under sudo this process is root, which [server] allowed_group does not
	// admit, so the question above can go unanswered exactly here.  The unit is
	// the same answer written down.
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

// errNoManagedFiles is what edit and rekey both report when the secrets
// directory is empty: neither has anything to open, and the fix is the same for
// both.
var errNoManagedFiles = errors.New("no managed sops files: [secrets] files named " +
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
		return "", fmt.Errorf("%s is not a managed file; [secrets] files names %s",
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
	return "", fmt.Errorf("no editor found; install one of %s or pass -editor",
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
func editManaged(target, keyPath, editorPath string) (bool, error) {
	// A tmpfs, so the plaintext never reaches a disk, and 0700 from MkdirTemp
	// keeps every other uid out while the editor has it open.
	dir, err := os.MkdirTemp("/dev/shm", "faramir-edit-")
	if err != nil {
		return false, fmt.Errorf("temporary directory: %w", err)
	}
	defer func() { _ = os.RemoveAll(dir) }()

	// The target's own name: .sops.yaml creation rules select by path_regex, and
	// anything else would match no rule and encrypt to no recipient.
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

	// The recipients the file already had, named explicitly: sops resolves
	// .sops.yaml by walking up from the file, which here is in a tmpfs, and an
	// edit should preserve who could read the file -- applying a changed
	// .sops.yaml is what `faramir rekey` is for.
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

// writeBack replaces the managed file without changing who owns it, written
// beside the target and renamed so a partial failure leaves no truncated store.
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

// runSops execs sops with the key as a path (SOPS_AGE_KEY_FILE), as the keeper
// supplies it, so it is absent from any environment block in /proc.  A fixed
// environment, since sops reads several variables naming a key or key source.
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

// chownLike gives the replacement the original's owner and group, so an edit
// does not hand the secrets directory back to root.
func chownLike(path string, info os.FileInfo) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return errors.New("cannot read the owner of the file being replaced")
	}
	return os.Chown(path, int(stat.Uid), int(stat.Gid))
}

// ageRecipient matches the recipient entries in a sops metadata block, in both
// encodings.  The metadata is cleartext, so this needs no key.
var ageRecipient = regexp.MustCompile(`recipient"?\s*:\s*"?(age1[0-9a-z]+)`)

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
