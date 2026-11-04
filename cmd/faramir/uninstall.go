package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/install"
)

func newUninstallCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "uninstall",
		Short:   "Unenrol every tree and remove the install, keeping the age key, the secrets and the log",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runUninstall()) },
	}
	return c
}

func runUninstall() int {
	if !requireRoot("uninstall") {
		return 1
	}
	// Nothing answering is not a reason to stop here, unlike every other command.
	// A first run removes the units before the sudoers grant, the PAM service and
	// the binaries, so a run that failed partway leaves exactly the host that
	// answers nothing, and that is the host the re-run is for. Uninstall removes
	// at fixed paths and wants the directory only for the enrolment record and
	// the agent account, and to name what it left in place: the compiled-in
	// default is a guess about which trees to unenrol rather than about what
	// gets deleted.
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintln(os.Stderr, "faramir uninstall: no install found; removing the default paths under "+
			hostlayout.DefaultConfigDir)
		dir = ""
	}
	report, err := install.Uninstall(dir)
	return reportUninstall(report, err)
}

func reportUninstall(report install.UninstallReport, err error) int {
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir uninstall: %v\n", err)
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	for _, dir := range report.Unenrolled {
		fmt.Fprintf(os.Stderr, "unenrolled %s\n", dir)
	}
	fmt.Fprintln(os.Stderr, "kept:")
	for _, item := range report.Kept {
		fmt.Fprintf(os.Stderr, "  %s\n", item)
	}
	if err != nil {
		return 1
	}
	return 0
}

func newReloadCmd() *cobra.Command {
	return &cobra.Command{
		Use:     "reload",
		Short:   "Stop the daemons; restart with current configuration on the next request",
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
