package main

import (
	"encoding/json"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
)

// newRefuseCmd groups what is done to a path the agent's file tools are refused
// and faramir never reads.
//
// Its own noun rather than a mode of `faramir link`, because the two differ in
// everything but the rule they render: a link grants the broker read, regroups
// the file so a brokered command is refused it, and puts the value in the
// redactor. This writes a rule. Naming that difference is the point.
func newRefuseCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "refuse",
		Short:   "Manage paths the agent's file tools are refused",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newRefuseAddCmd(), newRefuseRemoveCmd(), newRefuseListCmd())
	return c
}

type refuseFlags struct {
	configPath string
	agentUser  string
	json       bool
}

func (f *refuseFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.StringVar(&f.configPath, "config-dir", "",
		"the install to act on (default: where the running broker says it is)")
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
}

func newRefuseAddCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   "add [options] PATH",
		Short: "Refuse a path to the agent's file tools",
		Long: "Adds one [[secret.refuse]] entry and re-renders your agent's deny rules\n" +
			"so the path is refused to its file tools. For a credential faramir has no\n" +
			"use for the value of: a LUKS keyfile, an SSH identity.\n\n" +
			"The file is never opened. Nothing is granted to any account, the mode is\n" +
			"left as it is, and no value enters the redactor.\n\n" +
			"Which is the limit of it, and worth knowing: this stops the agent's own\n" +
			"file tools. A command the broker runs may still read the file if its mode\n" +
			"allows, and the output comes back in the clear, there being no value in\n" +
			"the redactor to match. `faramir link` is the entry that covers both, at\n" +
			"the price of faramir reading the value.\n\n" +
			"A path that is not there is still recorded, an unmounted volume being one\n" +
			"of the cases this exists for. You are told, since a typo looks the same.",
		Args: exactlyOneArg("path"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runRefuseAdd(f, args[0]))
		},
	}
	f.register(c)
	return c
}

func runRefuseAdd(f refuseFlags, path string) int {
	if !requireRoot("refuse add", "it writes the config and your agent's rule files") {
		return 1
	}
	report, err := install.AddRefused(refuseOptions(f), config.RefusedPath{Path: path})
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir refuse add: %v\n", err)
		return 1
	}
	printRefuseReport(report)
	// No reload. The daemons never read these entries: nothing is served out of
	// the path and nothing of it is redacted, so a restart would cost a running
	// command its broker for a change no daemon reads.
	fmt.Fprintf(os.Stderr, "refused %s\n", path)
	return 0
}

func newRefuseRemoveCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   "rm [options] PATH",
		Short: "Stop refusing a path",
		Long: "Removes the entry, so `faramir init` stops rendering the rule.\n\n" +
			"What it does not do is take the rule out of your agent's settings. Those\n" +
			"files are merged rather than replaced, and a merge can only add, so\n" +
			"nothing here can remove an entry from one. It is printed, with what would.",
		Args: exactlyOneArg("path"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runRefuseRemove(f, args[0])) },
	}
	f.register(c)
	return c
}

func runRefuseRemove(f refuseFlags, path string) int {
	if !requireRoot("refuse rm", "it writes the config") {
		return 1
	}
	report, removed, err := install.RemoveRefused(refuseOptions(f), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir refuse rm: %v\n", err)
		return 1
	}
	printRefuseReport(report)
	fmt.Fprintf(os.Stderr, "stopped refusing %s\n", removed.Path)
	fmt.Fprintf(os.Stderr, "the deny rule naming it stays in your agent's settings: "+
		"a merged rule file carries no sign of who added an entry, so nothing "+
		"removes one for you\n")
	return 0
}

func newRefuseListCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   "ls [options]",
		Short: "List the paths this install refuses",
		Args:  noArgs,
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runRefuseList(f)) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	return c
}

func runRefuseList(f refuseFlags) int {
	dir := refuseConfigDir(f)
	refused, err := install.RefusedPaths(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir refuse ls: %v\n", err)
		return 1
	}
	if f.json {
		body, err := json.MarshalIndent(refused, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir refuse ls: %v\n", err)
			return 1
		}
		fmt.Println(string(body))
		return 0
	}
	if len(refused) == 0 {
		fmt.Fprintln(os.Stderr, "no refused paths")
		return 0
	}
	// The same state column `link ls` carries, and for the same reason: whether
	// the path is there changes without anybody touching the config. Absent is
	// not a fault here, a rule waiting for a volume being the point.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PATH\tSTATE")
	for _, entry := range refused {
		state := "present"
		info, err := os.Stat(entry.Path)
		switch {
		case err != nil:
			state = "not there"
		case info.IsDir():
			state = "present (directory)"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", entry.Path, state)
	}
	_ = w.Flush()
	return 0
}

func refuseOptions(f refuseFlags) install.Options {
	return install.Options{
		ConfigDir: refuseConfigDir(f),
		AgentUser: operatorName(f.agentUser),
		Log:       func(line string) { fmt.Fprintln(os.Stderr, line) },
	}
}

func refuseConfigDir(f refuseFlags) string {
	return resolveConfigDir(f.configPath, socketDefault())
}

func printRefuseReport(report install.Report) {
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}
