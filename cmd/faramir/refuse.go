package main

import (
	"encoding/json"
	"errors"
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
		Long: "Adds one [[secret.refuse]] entry and re-renders your agent's deny rules,\n" +
			"so the path is refused to its file tools. For a credential faramir has no\n" +
			"use for the value of: a LUKS keyfile, an SSH identity.\n\n" +
			"The file is never opened: nothing is granted, the mode is left alone, and\n" +
			"no value enters the redactor. So this stops the agent's own file tools and\n" +
			"nothing else. A command the broker runs may still read the file if its\n" +
			"mode allows, and prints it in the clear. `faramir link` covers both, at\n" +
			"the price of faramir reading the value.\n\n" +
			"A path that is not there is still recorded, an unmounted volume being one\n" +
			"of the cases this exists for. You are told, since a typo looks the same.\n\n" +
			"A path this install already refuses is not an error: the entry stands, the\n" +
			"rules are rendered again, which is what restores one an agent's settings\n" +
			"dropped, and --json reports changed=false.",
		Args: exactlyOneArg("path"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runRefuseAdd(f, args[0]))
		},
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runRefuseAdd(f refuseFlags, path string) int {
	if !requireRoot("refuse add", "it writes the config and your agent's rule files") {
		return 1
	}
	report, added, err := install.AddRefusedPath(refuseOptions(f), config.RefusedPath{Path: path})
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir refuse add: %v\n", err)
	}
	if code := reportEntry(f.json, "refuse add", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	// No reload. The daemons never read these entries: nothing is served out of
	// the path and nothing of it is redacted, so a restart would cost a running
	// command its broker for a change no daemon reads.
	if f.json {
		return 0
	}
	if added {
		fmt.Fprintf(os.Stderr, "refused %s\n", path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s was already refused, so nothing was added; the rules "+
		"naming it were rendered again\n", path)
	return 0
}

func newRefuseRemoveCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   "rm [options] PATH",
		Short: "Stop refusing a path",
		Long: "Removes the entry, so `faramir init` stops rendering the rule.\n\n" +
			"It does not take the rule out of your agent's settings: those files are\n" +
			"merged rather than replaced, and a merge can only add. Remove that line\n" +
			"yourself, which this says on the way out.\n\n" +
			"A path this install does not refuse is not an error: nothing is written\n" +
			"and --json reports changed=false, the entry being gone either way.",
		Args: exactlyOneArg("path"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runRefuseRemove(f, args[0])) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runRefuseRemove(f refuseFlags, path string) int {
	if !requireRoot("refuse rm", "it writes the config") {
		return 1
	}
	report, removed, err := install.RemoveRefusedPath(refuseOptions(f), path)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir refuse rm: %v\n", err)
	}
	if code := reportEntry(f.json, "refuse rm", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	if f.json {
		return 0
	}
	if removed.Path == "" {
		fmt.Fprintf(os.Stderr, "%s was not refused, so nothing was removed; "+
			"`faramir refuse ls` lists the paths that are\n", path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "stopped refusing %s\n", removed.Path)
	fmt.Fprintf(os.Stderr, "the deny rule naming it stays in your agent's settings: "+
		"a merged rule file carries no sign of who added an entry, so nothing "+
		"removes one for you\n")
	return 0
}

func newRefuseListCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   useLs,
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
	//
	// "not there" means the path is not there, so a stat that failed for any
	// other reason says so instead: this command needs no root, and a refused
	// path under a directory only root can enter would otherwise read as an
	// entry waiting for a volume that is never coming.
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "PATH\tSTATE")
	for _, entry := range refused {
		state := "present"
		info, err := os.Stat(entry.Path)
		switch {
		case errors.Is(err, os.ErrNotExist):
			state = "not there"
		case err != nil:
			state = "cannot tell (" + errReason(err) + ")"
		case info.IsDir():
			state = "present (directory)"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\n", entry.Path, state)
	}
	_ = w.Flush()
	return 0
}

// errReason is why a stat failed, in the few words a table cell has room for.
func errReason(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "no permission to look"
	}
	return "stat failed"
}

func refuseOptions(f refuseFlags) install.Options {
	return install.Options{
		ConfigDir: refuseConfigDir(f),
		AgentUser: operatorName(f.agentUser),
		Log:       stepLog(f.json),
	}
}

func refuseConfigDir(f refuseFlags) string {
	return resolveConfigDir(f.configPath, socketDefault())
}
