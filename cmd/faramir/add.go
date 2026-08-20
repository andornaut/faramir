package main

// `faramir vault add` writes the first managed file, and every one after it.
// Running sops by hand instead leaves three things wrong, none of which
// announces itself: the plaintext source survives, the file lands 0644 where a
// managed one is 0640, and a name matching no [secret] pattern produces a valid
// encrypted file the broker never serves.
//
// So the editor is the way in, as it is for `edit`: the plaintext exists only
// in a 0600 file in /dev/shm and goes with the directory. --from is for the
// file somebody already holds, and says that the source is still cleartext.

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
)

// opAdd is the audit record a creation writes. Distinct from an edit: when a
// file entered the store is what an operator asks the log afterwards.
const opAdd = "add"

type addFlags struct {
	configPath string
	editor     string
	from       string
}

func newAddCmd() *cobra.Command {
	var f addFlags
	c := &cobra.Command{
		Use:   "add [options] NAME",
		Short: "Write a new managed sops file",
		Long: "Creates one file in the secrets directory, encrypted to the recipients\n" +
			".sops.yaml names.\n\n" +
			"NAME is a name, relative to the secrets directory: `.sops.yml` is added\n" +
			"for you, and a name that already carries it is taken as it stands.\n\n" +
			"The content comes from $EDITOR on a 0600 file in a tmpfs, so no plaintext\n" +
			"reaches a disk. --from encrypts a file you already have, and leaves it\n" +
			"where it is: it is still cleartext afterwards.",
		Args: exactlyArgs(1, "one file name"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runAdd(f, args[0])) },
	}
	c.Flags().StringVarP(&f.configPath, "config", "c", "",
		"config file (default $FARAMIR_CONFIG, then the installed one)")
	c.Flags().StringVar(&f.editor, "editor", "", "editor to run (default $VISUAL, $EDITOR, then vi)")
	c.Flags().StringVar(&f.from, "from", "",
		"encrypt this plaintext `FILE` instead of opening an editor; it is left where it is")
	return c
}

func runAdd(f addFlags, name string) int {
	const label = "vault add"
	if !requireRoot(label, "the age key is readable only by the keeper and by root") {
		return 1
	}
	cfg, err := config.Load(resolveConfig(f.configPath, socketDefault()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	target, err := newManagedPath(cfg, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}

	keyPath := ageKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: age key: %v\n", label, err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")

	editorPath := ""
	if f.from == "" {
		if editorPath, err = resolveEditor(f.editor); err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
	}

	err = addManaged(keyPath, rulePath, editorPath, f.from, target)
	record := map[string]any{
		"op": opAdd, "log_id": audit.NewLogID(), "file": target,
		"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
	}
	if editorPath != "" {
		record["editor"] = editorPath
	}
	if f.from != "" {
		record["from"] = f.from
	}
	if err != nil {
		record["error"] = err.Error()
	}
	// The file and where it came from, never what is in it.
	audit.NewLog(cfg.Audit).Write(record, audit.Output{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}

	fmt.Fprintf(os.Stderr, "faramir %s: wrote %s; the broker picks it up within one "+
		"refresh interval\n", label, target)
	if f.from != "" {
		// Said rather than done: removing somebody's file is not this command's to
		// decide, and a plaintext copy nobody remembers is what this exists to keep
		// off the disk.
		fmt.Fprintf(os.Stderr, "faramir %s: %s is still cleartext on disk\n", label, f.from)
	}
	return 0
}

// newManagedPath is where a new file goes, or why it may not go there.
// Relative to the secrets directory, which is the only place the broker reads,
// and checked against the patterns rather than the directory alone: a name the
// globs do not match encrypts perfectly well and is then served to nobody.
func newManagedPath(cfg *config.Config, name string) (string, error) {
	if len(cfg.Secret.Patterns) == 0 {
		return "", errors.New("[secret] patterns names no location for a managed file")
	}
	dir := filepath.Dir(cfg.Secret.Patterns[0])
	target := name
	if !filepath.IsAbs(target) {
		target = filepath.Join(dir, target)
	}
	target = filepath.Clean(target)

	// The suffix is faramir's, not the operator's: they pick a name and this
	// writes a YAML store. A name that already carries a managed suffix is taken
	// as it stands, so naming a file in full is neither wrong nor doubled.
	if !matchesPatterns(cfg.Secret.Patterns, target) {
		target += managedSuffix
	}
	if !matchesPatterns(cfg.Secret.Patterns, target) {
		return "", fmt.Errorf("%s matches none of the [secret] patterns (%s), so the "+
			"broker would never read it and nothing in it could be named as a ref. A "+
			"managed file lives in %s", target, joinPatterns(cfg.Secret.Patterns), dir)
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

// matchesPatterns reports whether the broker would read this path.
func matchesPatterns(patterns []string, target string) bool {
	for _, pattern := range patterns {
		if ok, _ := filepath.Match(pattern, target); ok {
			return true
		}
	}
	return false
}

func joinPatterns(patterns []string) string {
	out := make([]string, 0, len(patterns))
	for _, pattern := range patterns {
		out = append(out, filepath.Base(pattern))
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// addManaged writes the new file, with the plaintext living only in a tmpfs.
// The same shape as an edit minus the decrypt, and the recipients come from the
// rule rather than from the file, which has none yet.
func addManaged(keyPath, rulePath, editorPath, from, target string) error {
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

	recipients, err := ruleRecipients(rulePath)
	if err != nil {
		return err
	}
	// Asked before the editor opens, as an edit asks it: sops refuses a file no
	// creation rule covers at the encrypt, after everything has been typed.
	if err := ruleMustCover(rulePath, target, recipients); err != nil {
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
			return fmt.Errorf("read %s: %w", from, err)
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
