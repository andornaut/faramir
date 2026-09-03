package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/install"
)

type uninstallFlags struct {
}

func newUninstallCmd() *cobra.Command {
	var f uninstallFlags
	c := &cobra.Command{
		Use:     "uninstall [options]",
		Short:   "Remove the install, keeping the age key, the secrets directory and the log",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runUninstall(f)) },
	}
	return c
}

func runUninstall(f uninstallFlags) int {

	if !requireRoot("uninstall") {
		return 1
	}
	// Nothing answering is not a reason to stop here, unlike every other command.
	// A first run removes the units before the sudoers grant, the PAM service and
	// the binaries, so a run that failed partway leaves exactly the host that
	// answers nothing, and that is the host the re-run is for. Uninstall removes
	// at fixed paths and wants the directory only to name what it left in place,
	// where the compiled-in default is a guess about wording rather than about
	// what gets deleted.
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintln(os.Stderr, "faramir uninstall: no install answered; removing "+
			"from the default paths under "+hostlayout.DefaultConfigDir)
		dir = ""
	}
	left, err := install.Uninstall(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir uninstall: %v\n", err)
		return 1
	}
	fmt.Fprintln(os.Stderr, "\nLeft in place on purpose:")
	for _, item := range left {
		fmt.Fprintf(os.Stderr, "  %s\n", item)
	}
	fmt.Fprintln(os.Stderr, "\nRemove them by hand if you want to. Without the age key, "+
		"every managed sops file becomes unreadable.")
	return 0
}

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reload",
		Short:   "Stop the daemons so the next command starts them on the current configuration",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runReload()) },
	}
}

func runReload() int {

	if !requireRoot("reload") {
		return 1
	}
	if err := install.Reload(); err != nil {
		fmt.Fprintf(os.Stderr, "faramir reload: %v\n", err)
		return 1
	}
	return 0
}
