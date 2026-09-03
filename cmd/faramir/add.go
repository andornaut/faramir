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

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/brokerclient"
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
			"listed in .sops.yaml.\n\n" +
			"NAME is relative to the secrets directory. The `.sops.yml` suffix is\n" +
			"added unless NAME already ends with it.\n\n" +
			"The content is written in an editor, on a 0600 file in a tmpfs, so no\n" +
			"plaintext reaches a disk.\n\n" +
			"--from encrypts an existing file instead. That file is left where it is,\n" +
			"still in cleartext.",
		Args: exactlyArgs(1, "one file name"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runAdd(f, args[0])) },
	}
	c.Flags().StringVar(&f.editor, "editor", "", editorUsage)
	c.Flags().StringVar(&f.from, "from", "",
		"encrypt this plaintext `FILE` instead of opening an editor; the file is left where it is")
	return c
}

func runAdd(f addFlags, name string) int {
	const label = "vault add"
	if !requireRoot(label) {
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
		reReadNote(brokerclient.Refresh(socketDefault()), "it picks this up within one refresh interval"))
	if f.from != "" {
		// Said rather than done: removing somebody's file is not this command's to
		// decide, and a plaintext copy nobody remembers is what this exists to keep
		// off the disk.
		fmt.Fprintf(os.Stderr, "faramir %s: %s is still cleartext on disk\n", label, f.from)
	}
	return 0
}
