package main

// `faramir vault edit` changes a managed sops file once the secrets directory belongs
// to the secrets group and the operator does not. It runs sops itself rather
// than asking the keeper, which has no operation that returns key material;
// under sudo this process is already root.
//
// Over running sops by hand it adds: plaintext that is 0600 root in a tmpfs
// rather than readable by the uid the agent runs as; an editor held to
// resolveEditor's check, so what runs as root over the decrypted value is a
// binary no account but root can write, replace or hand an argument to; a path
// argument that cannot leave the managed set; and an audit record.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/auditview"
	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/vault"
)

type editFlags struct {
	editor string
}

func newEditCmd() *cobra.Command {
	var f editFlags
	c := &cobra.Command{
		Use:   "edit [options] FILE",
		Short: "Edit an encrypted secret file",
		Args:  exactlyOneArg("file"),
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runEdit(f, args)) },
	}
	c.Flags().StringVar(&f.editor, "editor", "", "absolute path to the editor to run, with no arguments "+
		"(default: $VISUAL, then $EDITOR, then the first of "+strings.Join(vault.Editors, ", ")+
		" that root alone can write; sudo's env_reset drops both variables unless the sudoers keep them)")
	return c
}

func runEdit(f editFlags, args []string) int {

	// Blocked rather than attempted: the bare permission error on the age key
	// does not say what to do.
	if !requireRoot("vault edit") {
		return 1
	}

	cfg, err := loadResolved(socketDefault())
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
	target, err := vault.Resolve(managed, args[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}

	editorPath, err := vault.ResolveEditor(f.editor)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: %v\n", err)
		return 1
	}

	keyPath := vault.AgeKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir vault edit: age key: %v\n", err)
		return 1
	}

	// The install's own rules, named rather than left to sops to find: see
	// runSops. The same file `reseal` reads, so the two agree about what governs
	// a managed file.
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")

	changed, err := vault.Edit(keyPath, rulePath, editorPath, target)
	record := map[string]any{
		"op": auditview.OpEdit,
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
	fmt.Fprintf(os.Stderr, "faramir vault edit: wrote %s; %s\n", target,
		reReadNote(brokerclient.Refresh(socketDefault()), "it picks this up within one refresh interval"))
	return 0
}

// loadResolved finds this host's config and loads it. The resolution failure is
// returned as the load failure: both say this command has no install to act on,
// and every caller prints them the same way.
//
// The same ladder the commands that act on the install climb, ending the same
// way, or a host whose config moved and whose unit is gone would have `faramir
// logs` read one install while `faramir block ls` refused to guess at another.
func loadResolved(socketPath string) (*config.Config, error) {
	path, err := findConfigFile(brokerclient.AskStatus(socketPath))
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}

// loadDaemonConfig is loadResolved for the three daemon entry points, which
// under systemd are pointed at their config by FARAMIR_CONFIG in the unit.
//
// The running broker is not a step here, unlike loadResolved: this process may
// be about to bind the broker's own socket, and connecting to it would
// socket-activate the installed daemon and leave the two contending for the
// path. The unit answers the same question without the round trip.
func loadDaemonConfig() (*config.Config, error) {
	// A zero status rather than one asked for, which is what skips the broker:
	// there is no separate ladder here, only one with its first rung unclimbed.
	path, err := findConfigFile(brokerclient.Status{})
	if err != nil {
		return nil, err
	}
	return config.Load(path)
}
