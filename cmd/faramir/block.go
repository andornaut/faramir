package main

import (
	"errors"
	"fmt"
	"os"
	"slices"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/termui"
)

// newBlockCmd groups what is done to a path the agent's file tools are blocked
// and faramir never reads.
//
// Its own noun rather than a mode of `faramir link`, because the two differ in
// everything but the rule they render: a link grants the broker read, regroups
// the file so a brokered command is refused it, and puts the value in the
// redactor. This writes a rule. Naming that difference is the point.
func newBlockCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "block",
		Short:   "Block paths and commands from the agent",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newBlockAddCmd(), newBlockRemoveCmd(), newBlockListCmd())
	return c
}

type blockFlags struct {
	paths    []string
	commands []string
	declared bool
	builtIn  bool
	json     bool
	when     string
	// strict tightens every path this invocation names. On add alone: rm takes
	// the entry out whichever strictness it carried.
	strict bool
}

// entries is the refusals a command was asked for: every --path and --command
// given, each one entry, in that order.
//
// Any number of either, and the two mix. One entry is a path or a command and
// never both, which the loader holds each of these to; an invocation is a list,
// so nothing here has to choose between the forms. A dozen paths in one command
// is what a first run pastes and what a converge hands over, and it costs one
// config rewrite rather than a dozen.
func (f *blockFlags) entries(verb string, args []string) ([]config.BlockedPath, error) {
	// A positional argument is refused rather than read as a path. The two forms
	// block different things and neither is the obvious one: an operator who
	// means a command and types the argument gets a rule about a file, which is
	// not what they asked for and looks like it worked.
	if len(args) > 0 {
		return nil, fmt.Errorf("faramir block %s: %q is not named as a form. Pass "+
			"--path for a file or directory on this host, or --command for "+
			"something the agent's shell may not run. The two block different "+
			"things, so neither of them is the default", verb, args[0])
	}
	out := make([]config.BlockedPath, 0, len(f.paths)+len(f.commands))
	// --strict rides on every path the command names, and on no command entry:
	// one invocation is one strictness, which is the only reading that does not
	// need an operator to remember which flag bound to which.
	for _, path := range f.paths {
		out = append(out, config.BlockedPath{Path: path, Strict: f.strict})
	}
	for _, command := range f.commands {
		out = append(out, config.BlockedPath{Command: command})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("faramir block %s: name a path with --path or a "+
			"command with --command. A path blocks that file or directory on this "+
			"host; a command blocks the agent's shell from running it. Each may be "+
			"given more than once, and they mix", verb)
	}
	return out, nil
}

// registerForms is on add and rm and not on ls, which takes none of them. Each
// form is a flag, including the path: two things are blocked here and a
// positional argument would make one of them the default.
func (f *blockFlags) registerForms(c *cobra.Command) {
	c.Flags().StringArrayVar(&f.paths, "path", nil,
		"an absolute path to a file or directory on this host; repeatable")
	c.Flags().StringArrayVar(&f.commands, "command", nil,
		"a command the agent may not run, as it would be typed "+
			"(\"op read\"); the words are literal, not a pattern; repeatable")
}

func newBlockAddCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   "add [options] (--path PATH | --command COMMAND)...",
		Short: "Block one path or command from the agent",
		Long: "Adds one [[secret.block]] entry per --path and --command, then\n" +
			"re-renders the agent's deny rules. Use it for a credential whose value\n" +
			"faramir never needs, such as a LUKS keyfile or an SSH identity.\n\n" +
			"The file is never opened, so its value never enters the redactor. A\n" +
			"blocked path is refused to the agent's file tools, to its shell, and to\n" +
			"any brokered command that would print it. Other brokered commands are\n" +
			"allowed, including ones that move or overwrite the file. --strict refuses\n" +
			"every command that names the path.\n\n" +
			"A bare argument is refused. A path that does not exist is still recorded,\n" +
			"and reported. An entry that already exists re-renders the rules and\n" +
			"reports changed=false.\n\n" +
			"Prints the path it blocked. --json prints the file-by-file report.",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runBlockAdd(f, args))
		},
	}
	f.registerForms(c)
	c.Flags().BoolVar(&f.strict, "strict", false,
		"refuse every command that names these paths, not only the ones that "+
			"would print them: ls, stat, chmod and mv included. Off by default, "+
			"since a file nothing may touch cannot be rotated. Not for --command, "+
			"which already matches at the start of a command only")
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runBlockAdd(f blockFlags, args []string) int {
	if !requireRoot("block add") {
		return 1
	}
	blocked, err := f.entries("add", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block add: %v\n", err)
		return 1
	}
	report, added, err := install.AddBlockedPaths(installOptions(dir), blocked)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block add: %v\n", err)
	}
	if code := reportDocument(f.json, "block add", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	// The broker holds these entries itself and compiles them once, at start, so
	// an entry added into a running install is not refused until it reloads.
	// Only when something changed: a re-assert that found the host as it should
	// be has nothing new for a daemon to read, and reloading would restart them
	// under whatever brokered command is running.
	if report.Changed {
		if err := install.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "faramir block add: entry written, daemons not "+
				"reloaded, so it is not enforced yet: %v\n", err)
			return 1
		}
	}
	if f.json {
		return 0
	}
	// A line each, in the order they were given: a list where some were already
	// there and some were not is the ordinary case for a converge, and a count
	// would not say which was which.
	for i, entry := range blocked {
		if added[i] {
			fmt.Fprintf(os.Stderr, "blocked %s\n", config.Shown(entry.Blocks()))
			continue
		}
		fmt.Fprintf(os.Stderr, "already blocked: %s\n", config.Shown(entry.Blocks()))
	}
	printWarnings(report)
	return 0
}

func newBlockRemoveCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   "rm [options] (--path PATH | --command COMMAND)...",
		Short: "Unblock one path or command",
		Long: "Removes the entry, so `faramir init` stops rendering the rule.\n\n" +
			"Needs root, because it writes the config. The rules faramir wrote into\n" +
			"your agent's settings are removed with it, using its record of what it\n" +
			"last wrote there. A rule you added yourself for the same path is not in\n" +
			"that record and stays.\n\n" +
			"Prints the path it stopped blocking. --json prints the file-by-file\n" +
			"report.\n\n" +
			"The flag identifies the entry: --command does not remove a --path entry\n" +
			"with the same text. An entry that does not exist reports changed=false.\n" +
			"A rule built into faramir cannot be removed; `faramir block ls` shows\n" +
			"which rules are built in.",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runBlockRemove(f, args)) },
	}
	f.registerForms(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runBlockRemove(f blockFlags, args []string) int {
	asked, err := f.entries("rm", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	// Before root, not after: these can never be granted, so making the operator
	// find sudo to be told so is a round trip for nothing. It reads the config,
	// which needs no root either, because an entry the install declares is
	// removable whatever else refuses the same file. Every one of them, so a list
	// carrying a built-in is refused whole rather than halfway through.
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block rm: %v\n", err)
		return 1
	}
	for _, entry := range asked {
		if err := install.BuiltInRuleError(dir, entry); err != nil {
			fmt.Fprintf(os.Stderr, "faramir block rm: %v\n", err)
			return 1
		}
	}
	if !requireRoot("block rm") {
		return 1
	}
	report, removed, err := install.RemoveBlockedPaths(installOptions(dir), asked)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block rm: %v\n", err)
	}
	if code := reportDocument(f.json, "block rm", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	// The other direction of the same staleness: until the broker reloads it goes
	// on refusing a path the operator has just undeclared.
	if report.Changed {
		if err := install.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "faramir block rm: entry removed, daemons not "+
				"reloaded, so it is still refused: %v\n", err)
			return 1
		}
	}
	if f.json {
		return 0
	}
	// The outcome first and on its own: it is the answer to what was asked, and
	// an operator who has to find it under a dozen paths has been told nothing.
	// Everything below it is about how, and only where it applies.
	for i, entry := range removed {
		if entry.Blocks() == "" {
			fmt.Fprintf(os.Stderr, "not blocked: %s; `faramir block ls` lists what is\n",
				config.Shown(asked[i].Blocks()))
			continue
		}
		fmt.Fprintf(os.Stderr, "stopped blocking %s\n", config.Shown(entry.Blocks()))
	}
	printWarnings(report)
	// Said only where an agent's settings were actually rewritten. Where nothing
	// there changed there is no merge to explain, and the paragraph described a
	// mechanism that had not run.
	//
	// Both steps, because either writes an agent's settings: the account-wide
	// files on a home that has an agent in it, and the per-tree files on every
	// enrolled tree. A host with no agent in the home still has trees, and
	// asking only the first said nothing on the run that had just rewritten one.
	if changedAny(report, "agent config", "enrolled trees") {
		fmt.Fprintln(os.Stderr, noteHandWrittenRule)
	}
	return 0
}

// changedAny reports whether any of the named steps changed anything, so a note
// about what a step did is printed only on a run where it did it.
func changedAny(report install.Report, names ...string) bool {
	for _, step := range report.Steps {
		if slices.Contains(names, step.Name) && step.Changed {
			return true
		}
	}
	return false
}

func newBlockListCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List the blocked paths and commands",
		Long: "Lists everything this host blocks: the [[secret.block]] entries it\n" +
			"declares, in a table, then the rules built into faramir. --json prints\n" +
			"one list with a `source` field per row.\n\n" +
			"The kind says where a rule is enforced. A `path` rule applies to the\n" +
			"agent's file tools and its shell; a `command` rule applies to the shell\n" +
			"only.\n\n" +
			"--declared lists only the entries a configuration manager can converge.\n" +
			"--built-in lists only the rules no config names and no `block rm`\n" +
			"removes. Passing both is refused; leaving both out lists everything.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runBlockList(f)) },
	}
	c.Flags().BoolVar(&f.declared, "declared", false,
		"list only the [[secret.block]] entries this install declares")
	c.Flags().BoolVar(&f.builtIn, "built-in", false,
		"list only the rules built into faramir, which no entry declares")
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	addColorFlag(c, &f.when)
	return c
}

func runBlockList(f blockFlags) int {
	paint, bad := termui.PaletteFor("block ls", f.when)
	if bad != 0 {
		return bad
	}
	// Both halves is the default, so naming both narrows to everything and says
	// nothing. Refused rather than answered, a caller that wrote both having
	// meant one of them.
	if f.declared && f.builtIn {
		fmt.Fprintln(os.Stderr, "faramir block ls: pass --declared or --built-in, "+
			"not both; neither lists both halves")
		return 2
	}
	dir, err := installedConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block ls: %v\n", err)
		return 1
	}
	declared, err := install.BlockedPaths(dir)
	if err != nil {
		// The built-in rules are compiled in and hold whatever the config says, so
		// they are still worth printing where it could not be read. --declared
		// asked for the half that is missing, so that form fails.
		if f.declared {
			fmt.Fprintf(os.Stderr, "faramir block ls: %v\n", err)
			return 1
		}
		fmt.Fprintf(os.Stderr, "faramir block ls: %v; the built-in rules below are "+
			"compiled in and hold regardless\n", err)
	}
	if f.builtIn {
		declared = nil
	}
	rows := blockRows(dir, declared, !f.declared)
	if f.json {
		// [] rather than null, for the reason `link ls` gives.
		if rows == nil {
			rows = []blockRow{}
		}
		return printJSON("block ls", rows)
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no [[secret.block]] entries")
		return 0
	}
	// The table is what this host declared. The built-ins go under it, by kind:
	// the command rules are regular expressions, one long enough that a cell
	// holding it would take the alignment of every other row with it, and the
	// paths are faramir's own rather than an entry anybody can remove.
	var builtIn []blockRow
	table := [][]termui.Cell{{
		termui.Painted("KIND", paint.Key), termui.Painted("ENTRY", paint.Key),
	}}
	for _, row := range rows {
		if row.belowTable() {
			builtIn = append(builtIn, row)
			continue
		}
		// The entry is unpainted: it is what the operator wrote, and the colour
		// stops where faramir's own words stop.
		//
		// Strictness rides in the kind cell rather than in a column of its own:
		// it is the difference between a refusal a reader expected and one they
		// did not, and a column that is empty on most rows costs the width of its
		// heading on all of them.
		kind := row.Kind
		if row.Strict {
			kind += " (strict)"
		}
		table = append(table, []termui.Cell{
			termui.Painted(kind, paint.Bold), termui.Value(row.Entry),
		})
	}
	declaredTable := len(table) > 1
	if declaredTable {
		termui.PrintTable(os.Stdout, table)
	}
	printBuiltIn(paint, builtIn, declaredTable)
	return 0
}

// errReason is why a stat failed, in the few words a table cell has room for.
func errReason(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "no permission to look"
	}
	return "stat failed"
}
