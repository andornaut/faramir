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
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/vault"
)

// opAdd is the audit record a creation writes. Distinct from an edit: when a
// file entered the store is what an operator asks the log afterwards.
const opAdd = "add"

type addFlags struct {
	editor string
	from   string
}

func newAddCmd() *cobra.Command {
	var f addFlags
	c := &cobra.Command{
		Use:   "add [options] NAME",
		Short: "Add a new encrypted secret file",
		Long: "Creates one file in the secrets directory, encrypted to the recipients\n" +
			".sops.yaml names.\n\n" +
			"NAME is a name, relative to the secrets directory: `.sops.yml` is added\n" +
			"for you, and a name that already carries it is taken as it stands.\n\n" +
			"The content comes from an editor faramir picks, on a 0600 file in a\n" +
			"tmpfs, so no plaintext reaches a disk. That editor runs as root over the\n" +
			"decrypted value, so it must be a binary no account but root can write or\n" +
			"replace: --editor, $VISUAL and $EDITOR each name one by absolute path and\n" +
			"are each held to that.\n\n" +
			"--from encrypts a file you already have and leaves it cleartext where it\n" +
			"is.",
		Args: exactlyArgs(1, "one file name"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runAdd(f, args[0])) },
	}
	c.Flags().StringVar(&f.editor, "editor", "", "absolute path to the editor to run, with no arguments "+
		"(default: $VISUAL, then $EDITOR, then the first of "+strings.Join(vault.Editors, ", ")+
		" that root alone can write; sudo's env_reset drops both variables unless the sudoers keep them)")
	c.Flags().StringVar(&f.from, "from", "",
		"encrypt this plaintext `FILE` instead of opening an editor; it is left where it is")
	return c
}

func runAdd(f addFlags, name string) int {
	const label = "vault add"
	if !requireRoot(label, "the age key is readable only by the keeper and by root") {
		return 1
	}
	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	target, err := vault.NewManagedPath(cfg, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}

	keyPath := vault.AgeKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: age key: %v\n", label, err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")

	editorPath := ""
	if f.from == "" {
		if editorPath, err = vault.ResolveEditor(f.editor); err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
	}

	err = vault.Add(keyPath, rulePath, editorPath, f.from, target)
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

	fmt.Fprintf(os.Stderr, "faramir %s: wrote %s; %s\n", label, target,
		reReadNote(tellBrokerToReRead(), "it picks this up within one refresh interval"))
	if f.from != "" {
		// Said rather than done: removing somebody's file is not this command's to
		// decide, and a plaintext copy nobody remembers is what this exists to keep
		// off the disk.
		fmt.Fprintf(os.Stderr, "faramir %s: %s is still cleartext on disk\n", label, f.from)
	}
	return 0
}
