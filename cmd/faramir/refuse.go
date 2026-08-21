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
	name       string
	declared   bool
	json       bool
}

// entry is the refusal a command was asked for, or the error naming which of
// the two forms was missing or doubled. Exactly one: --name and a path render
// different rules, so an entry carrying both is two entries written as one.
func (f *refuseFlags) entry(verb string, args []string) (config.RefusedPath, error) {
	switch {
	case f.name != "" && len(args) > 0:
		return config.RefusedPath{}, fmt.Errorf("faramir refuse %s: --name %s and "+
			"path %s were both given, and an entry is one or the other: a path "+
			"refuses that file on this host, a name refuses every file it matches "+
			"wherever it is. Run it twice", verb, f.name, args[0])
	case f.name != "":
		return config.RefusedPath{Name: f.name}, nil
	case len(args) == 1:
		return config.RefusedPath{Path: args[0]}, nil
	}
	return config.RefusedPath{}, fmt.Errorf("faramir refuse %s: name a path, or a "+
		"pattern with --name. A path refuses that file on this host; a name "+
		"refuses every file whose name matches it, wherever it turns up, which is "+
		"what reaches a path this host does not have", verb)
}

func (f *refuseFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.StringVar(&f.configPath, "config-dir", "",
		"the install to act on (default: where the running broker says it is)")
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
}

// registerName is on add and rm and not on ls, which takes neither form.
func (f *refuseFlags) registerName(c *cobra.Command) {
	c.Flags().StringVar(&f.name, "name", "",
		"refuse a file name, suffix (*.pem), prefix (.env*), name with a wildcard "+
			"(secrets*.yml) or directory (.storage/) instead of a path")
}

func newRefuseAddCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   "add [options] PATH | --name PATTERN",
		Short: "Refuse a path or a name to the agent's file tools",
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
			"dropped, and --json reports changed=false.\n\n" +
			"--name refuses a name rather than a path, matched against what the agent\n" +
			"names rather than against this host: a container mounts a directory\n" +
			"somewhere of its own, and only the name reaches the path it runs against.\n" +
			"It is the wider form and nothing announces one that matches too much, so\n" +
			"what a pattern will match is printed as it is written.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runRefuseAdd(f, args))
		},
	}
	f.register(c)
	f.registerName(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runRefuseAdd(f refuseFlags, args []string) int {
	if !requireRoot("refuse add", "it writes the config and your agent's rule files") {
		return 1
	}
	refused, err := f.entry("add", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	path := refused.Refuses()
	report, added, err := install.AddRefusedPath(refuseOptions(f), refused)
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
		Use:   "rm [options] PATH | --name PATTERN",
		Short: "Stop refusing a path or a name",
		Long: "Removes the entry, so `faramir init` stops rendering the rule.\n\n" +
			"It does not take the rule out of your agent's settings: those files are\n" +
			"merged rather than replaced, and a merge can only add. Remove that line\n" +
			"yourself, which this says on the way out.\n\n" +
			"A path this install does not refuse is not an error: nothing is written\n" +
			"and --json reports changed=false, the entry being gone either way.\n\n" +
			"--name removes a name entry. The form is part of what identifies one, so\n" +
			"a name is not removed by giving the same string as a path.",
		Args: cobra.MaximumNArgs(1),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runRefuseRemove(f, args)) },
	}
	f.register(c)
	f.registerName(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runRefuseRemove(f refuseFlags, args []string) int {
	if !requireRoot("refuse rm", "it writes the config") {
		return 1
	}
	asked, err := f.entry("rm", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	path := asked.Refuses()
	report, removed, err := install.RemoveRefusedPath(refuseOptions(f), asked)
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
	if removed.Refuses() == "" {
		fmt.Fprintf(os.Stderr, "%s was not refused, so nothing was removed; "+
			"`faramir refuse ls` lists what is\n", path)
		return 0
	}
	fmt.Fprintf(os.Stderr, "stopped refusing %s\n", removed.Refuses())
	fmt.Fprintf(os.Stderr, "the deny rule naming it stays in your agent's settings: "+
		"a merged rule file carries no sign of who added an entry, so nothing "+
		"removes one for you\n")
	return 0
}

func newRefuseListCmd() *cobra.Command {
	var f refuseFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List what the agent's file tools are refused",
		Long: "Lists both halves of what an agent's file tools are refused: the rules\n" +
			"compiled into faramir, and the [[secret.refuse]] entries this install\n" +
			"declares. The SOURCE column says which is which.\n\n" +
			"The built-in rules are shown because there is otherwise no way to ask\n" +
			"what they cover: the agent meets one as a file tool refusing a path, and\n" +
			"a refusal names the rule that matched rather than the set. A rule nobody\n" +
			"can enumerate is one that gets declared a second time, or reported as a\n" +
			"gap that was never open.\n\n" +
			"--declared narrows this to the entries the config carries, which is the\n" +
			"list a configuration manager converges.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runRefuseList(f)) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.declared, "declared", false,
		"only the [[secret.refuse]] entries this install declares")
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	return c
}

// refusalRow is one line of `refuse ls`, and the JSON a configuration manager
// asserts on. Source and kind are separate fields rather than one string: a
// caller filtering to what it declared should not have to parse prose.
type refusalRow struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Entry  string `json:"entry"`
	// State is whether the path is there, for a path entry alone. A name is not
	// asked of this filesystem at all.
	State string `json:"state,omitempty"`
	// Detail is what a built-in protects or what a pattern matches, whichever
	// the row is.
	Detail string `json:"detail,omitempty"`
}

// refusalRows is the listing, declared entries first: they are what the
// operator wrote and what a converge acts on, and the built-in list is long
// enough to push them off a screen.
func refusalRows(declared []config.RefusedPath, builtIn bool) []refusalRow {
	rows := make([]refusalRow, 0, len(declared)+len(install.BuiltInRefusals()))
	for _, entry := range declared {
		if entry.Name != "" {
			rows = append(rows, refusalRow{
				Source: "declared", Kind: install.RefusedNameKind(entry.Name),
				Entry: entry.Name, Detail: install.RefusedNameMatches(entry.Name),
			})
			continue
		}
		rows = append(rows, refusalRow{
			Source: "declared", Kind: "path", Entry: entry.Path,
			State: refusedPathState(entry.Path),
		})
	}
	if !builtIn {
		return rows
	}
	for _, rule := range install.BuiltInRefusals() {
		rows = append(rows, refusalRow{
			Source: "built-in", Kind: rule.Kind, Entry: rule.Entry, Detail: rule.Why,
		})
	}
	return rows
}

// refusedPathState is whether a declared path is there. The same state `link
// ls` carries, and for the same reason: it changes without anybody touching the
// config, and absent is not a fault here, a rule waiting for a volume being the
// point.
//
// "not there" means the path is not there, so a stat that failed for any other
// reason says so instead: this command needs no root, and a refused path under
// a directory only root can enter would otherwise read as an entry waiting for
// a volume that is never coming.
func refusedPathState(path string) string {
	info, err := os.Stat(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return "not there"
	case err != nil:
		return "cannot tell (" + errReason(err) + ")"
	case info.IsDir():
		return "present (directory)"
	}
	return "present"
}

func runRefuseList(f refuseFlags) int {
	dir := refuseConfigDir(f)
	declared, err := install.RefusedPaths(dir)
	if err != nil {
		// The built-in rules are compiled in and hold whatever the config says, so
		// they are still worth printing where it could not be read. --declared
		// asked for the half that is missing, so that form fails.
		if f.declared {
			fmt.Fprintf(os.Stderr, "faramir refuse ls: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "faramir refuse ls: %v; the built-in rules below are "+
			"compiled in and hold regardless\n", err)
	}
	rows := refusalRows(declared, !f.declared)
	if f.json {
		// [] rather than null, for the reason `link ls` gives.
		if rows == nil {
			rows = []refusalRow{}
		}
		body, marshalErr := json.MarshalIndent(rows, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "faramir refuse ls: %v\n", marshalErr)
			return 1
		}
		fmt.Println(string(body))
		return 0
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no [[secret.refuse]] entries; `faramir refuse ls` "+
			"without --declared lists the rules compiled in")
		return 0
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SOURCE\tKIND\tENTRY\tNOTES")
	for _, row := range rows {
		notes := row.Detail
		if row.State != "" {
			notes = row.State
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", row.Source, row.Kind, row.Entry, notes)
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
