package main

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/enrol"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// enrolFlags is one `enrol` run. The tree defaults to the working
// directory, which is safe here and not on init: that one means "provision this
// host" and would otherwise enrol wherever it was run from.
type enrolFlags struct {
	clientGroup string
	agents      []string
	dryRun      bool
	asJSON      bool
}

func newEnrolCmd() *cobra.Command {
	var f enrolFlags
	c := &cobra.Command{
		Use:     "enrol [options] [DIR]",
		Short:   "Set up one working tree and configure its agents",
		GroupID: groupOperator,
		Args:    atMostOneArg("directory"),
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runEnrol(f, args)) },
	}
	fl := c.Flags()
	// No --agent-user. The tree belongs to the account this host belongs to, which
	// [server] agent_user records; `faramir init --agent-user` is what names it.
	fl.StringVar(&f.clientGroup, "client-group", "",
		"share the tree with this group instead of the installed config's client group; "+
			"the config must still load")
	fl.StringArrayVar(&f.agents, "agent", nil,
		"coding agent to enrol; repeatable. \""+agentcfg.Auto+"\" (the default) means "+
			"every agent this tree already has configuration for, and Codex when your "+
			"home has it. A name enrols that "+
			"agent whether or not it is there, and can be combined with auto. "+
			"Known: "+strings.Join(agentcfg.Known(), ", "))
	fl.BoolVar(&f.dryRun, "dry-run", false, "report what would change and write nothing")
	fl.BoolVar(&f.asJSON, "json", false, "print the report as JSON")
	return c
}

func runEnrol(f enrolFlags, args []string) int {
	// A dry run writes nothing, so it has no wrong install to act on: asking
	// about a tree from a host that has not been provisioned yet is what it is
	// for, and Project takes the same latitude with a config it cannot read.
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		if !f.dryRun {
			fmt.Fprintf(os.Stderr, "faramir enrol: %v\n", err)
			return 1
		}
		dir = hostlayout.DefaultConfigDir
	}

	opts := enrol.Options{
		Dir:         firstArg(args),
		AgentUser:   operatorFromConfig(filepath.Join(dir, "config.toml")),
		ConfigDir:   dir,
		ClientGroup: f.clientGroup,
		Agents:      f.agents,
		DryRun:      f.dryRun,
	}
	if !f.asJSON {
		opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
	}

	report, projectErr := enrol.Tree(opts)
	// The failure before the document; see runInit.
	if projectErr != nil {
		reportErr("enrol", projectErr)
	}
	if f.asJSON {
		if code := printJSON("enrol", report); code != 0 {
			return code
		}
	}
	if projectErr != nil {
		return 1
	}
	if !f.asJSON {
		for _, warning := range report.Warnings {
			fmt.Fprintf(os.Stderr, "\nWARNING: %s\n", warning)
		}
		if report.DryRun {
			fmt.Fprintf(os.Stderr, "\nDry run: nothing was written. %s would be "+
				"enrolled with group %s.\n", report.Dir, report.ClientGroup)
		} else {
			fmt.Fprintf(os.Stderr, "\nEnrolled %s with group %s.\n",
				report.Dir, report.ClientGroup)
			fmt.Fprintln(os.Stderr, "Check it: cd there and run `faramir run -- pwd`.")
		}
	}
	return 0
}
