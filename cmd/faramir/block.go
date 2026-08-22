package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/guard"
	"github.com/andornaut/faramir/internal/install"
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
		Short:   "Block paths and names from the agent's file tools",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newBlockAddCmd(), newBlockRemoveCmd(), newBlockListCmd())
	return c
}

type blockFlags struct {
	configPath string
	agentUser  string
	names      []string
	commands   []string
	declared   bool
	json       bool
}

// entries is the refusals a command was asked for: every path given as an
// argument and every --name given as a flag, each one entry, in that order.
//
// Any number of either, and the two mix. One entry is a path or a name and
// never both, which the loader holds each of these to; an invocation is a list,
// so nothing here has to choose between the forms. A dozen names in one command
// is what a first run pastes and what a converge hands over, and it costs one
// config rewrite rather than a dozen.
func (f *blockFlags) entries(verb string, args []string) ([]config.BlockedPath, error) {
	out := make([]config.BlockedPath, 0, len(args)+len(f.names))
	for _, path := range args {
		out = append(out, config.BlockedPath{Path: path})
	}
	for _, name := range f.names {
		out = append(out, config.BlockedPath{Name: name})
	}
	for _, command := range f.commands {
		out = append(out, config.BlockedPath{Command: command})
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("faramir block %s: name a path, or a pattern with "+
			"--name, or a command with --command. A path blocks that file on this "+
			"host; a name blocks every file whose name matches it, wherever it "+
			"turns up, which is what reaches a path this host does not have; a "+
			"command blocks the agent's shell from running it. Each may be given "+
			"more than once", verb)
	}
	return out, nil
}

func (f *blockFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.StringVar(&f.configPath, "config-dir", "",
		"the install to act on (default: where the running broker says it is)")
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
}

// registerName is on add and rm and not on ls, which takes neither form.
func (f *blockFlags) registerName(c *cobra.Command) {
	c.Flags().StringArrayVar(&f.names, "name", nil,
		"a file name, suffix (*.pem), prefix (.env*), name with a wildcard "+
			"(secrets*.yml) or directory (.storage/) rather than a path; repeatable")
	c.Flags().StringArrayVar(&f.commands, "command", nil,
		"a command the agent's shell may not run, as it would be typed "+
			"(\"op read\"); the words are literal, not a pattern; repeatable")
}

func newBlockAddCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   "add [options] [PATH...] [--name PATTERN]...",
		Short: "Block a path or a name from the agent's file tools",
		Long: "Adds a [[secret.block]] entry per path and per --name given, and\n" +
			"re-renders your agent's deny rules, so each is blocked from its file tools.\n" +
			"For a credential faramir has no use for the value of: a LUKS keyfile, an\n" +
			"SSH identity.\n\n" +
			"The file is never opened: nothing is granted, the mode is left alone, and\n" +
			"no value enters the redactor. So this stops the agent's own file tools and\n" +
			"nothing else. A command the broker runs may still read the file if its\n" +
			"mode allows, and prints it in the clear. `faramir link` covers both, at\n" +
			"the price of faramir reading the value.\n\n" +
			"A path that is not there is still recorded, an unmounted volume being one\n" +
			"of the cases this exists for. You are told, since a typo looks the same.\n\n" +
			"A path this install already blocks is not an error: the entry stands, the\n" +
			"rules are rendered again, which is what restores one an agent's settings\n" +
			"dropped, and --json reports changed=false.\n\n" +
			"Any number of paths and any number of --name patterns, in one command:\n" +
			"each is its own entry, and the config and your agent's rule files are\n" +
			"written once rather than once per entry.\n\n" +
			"--name blocks a name rather than a path, matched against what the agent\n" +
			"names rather than against this host: a container mounts a directory\n" +
			"somewhere of its own, and only the name reaches the path it runs against.\n" +
			"It is the wider form and nothing announces one that matches too much, so\n" +
			"what a pattern will match is printed as it is written.",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runBlockAdd(f, args))
		},
	}
	f.register(c)
	f.registerName(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runBlockAdd(f blockFlags, args []string) int {
	if !requireRoot("block add", "it writes the config and your agent's rule files") {
		return 1
	}
	blocked, err := f.entries("add", args)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	report, added, err := install.AddBlockedPaths(blockOptions(f), blocked)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block add: %v\n", err)
	}
	if code := reportEntry(f.json, "block add", report); code != 0 {
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
	// A line each, in the order they were given: a list where some were already
	// there and some were not is the ordinary case for a converge, and a count
	// would not say which was which.
	for i, entry := range blocked {
		if added[i] {
			fmt.Fprintf(os.Stderr, "blocked %s\n", entry.Blocks())
			continue
		}
		fmt.Fprintf(os.Stderr, "%s was already blocked, so nothing was added; the "+
			"rules naming it were rendered again\n", entry.Blocks())
	}
	return 0
}

func newBlockRemoveCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   "rm [options] [PATH...] [--name PATTERN]...",
		Short: "Stop blocking a path or a name",
		Long: "Removes the entry, so `faramir init` stops rendering the rule.\n\n" +
			"It does not take the rule out of your agent's settings: those files are\n" +
			"merged rather than replaced, and a merge can only add. Remove that line\n" +
			"yourself, which this says on the way out.\n\n" +
			"A path this install does not block is not an error: nothing is written\n" +
			"and --json reports changed=false, the entry being gone either way.\n\n" +
			"Any number of either, as `add` takes them.\n\n" +
			"--name removes a name entry. The form is part of what identifies one, so\n" +
			"a name is not removed by giving the same string as a path.\n\n" +
			"A rule compiled into faramir cannot be removed and is refused rather than\n" +
			"reported as not blocked: it is not an entry, and this host goes on blocking\n" +
			"what was named, and saying nothing was removed would read as saying the\n" +
			"file became readable. `faramir block ls` shows which rules are which.",
		Args: cobra.ArbitraryArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runBlockRemove(f, args)) },
	}
	f.register(c)
	f.registerName(c)
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
	for _, entry := range asked {
		if err := install.BuiltInRuleError(blockConfigDir(f), entry); err != nil {
			fmt.Fprintf(os.Stderr, "faramir block rm: %v\n", err)
			return 1
		}
	}
	if !requireRoot("block rm", "it writes the config") {
		return 1
	}
	report, removed, err := install.RemoveBlockedPaths(blockOptions(f), asked)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir block rm: %v\n", err)
	}
	if code := reportEntry(f.json, "block rm", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	if f.json {
		return 0
	}
	var gone bool
	for i, entry := range removed {
		if entry.Blocks() == "" {
			fmt.Fprintf(os.Stderr, "%s was not blocked, so nothing was removed; "+
				"`faramir block ls` lists what is\n", asked[i].Blocks())
			continue
		}
		gone = true
		fmt.Fprintf(os.Stderr, "stopped blocking %s\n", entry.Blocks())
	}
	if gone {
		fmt.Fprintf(os.Stderr, "the deny rules naming them stay in your agent's "+
			"settings: a merged rule file carries no sign of who added an entry, so "+
			"nothing removes one for you\n")
	}
	return 0
}

func newBlockListCmd() *cobra.Command {
	var f blockFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List what the agent's file tools are blocked",
		Long: "Lists both halves of what an agent's file tools are refused: the rules\n" +
			"compiled into faramir, and the [[secret.block]] entries this install\n" +
			"declares. The SOURCE column says which is which.\n\n" +
			"The built-in rules are shown because there is otherwise no way to ask\n" +
			"what they cover: the agent meets one as a file tool refusing a path, and\n" +
			"a refusal names the rule that matched rather than the set. A rule nobody\n" +
			"can enumerate is one that gets declared a second time, or reported as a\n" +
			"gap that was never open.\n\n" +
			"--declared narrows this to the entries the config carries, which is the\n" +
			"list a configuration manager converges.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runBlockList(f)) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.declared, "declared", false,
		"only the [[secret.block]] entries this install declares")
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	return c
}

// blockRow is one line of `block ls`, and the JSON a configuration manager
// asserts on. Source and kind are separate fields rather than one string: a
// caller filtering to what it declared should not have to parse prose.
type blockRow struct {
	Source string `json:"source"`
	Kind   string `json:"kind"`
	Entry  string `json:"entry"`
	// Covers says which entry point the row is enforced at. Both for anything
	// this install protects, the agents' rules and the command guard's patterns
	// being rendered from one set; commands alone for a rule about what a
	// command does rather than what it names.
	Covers string `json:"covers"`
	// State is whether the path is there, for a path entry alone. A name is not
	// asked of this filesystem at all.
	//
	// JSON only, as Detail is. The table is four columns of what is blocked and
	// where; whether a file happens to exist today is a different question, and
	// a fifth column answering it made the rows long enough to wrap.
	State string `json:"state,omitempty"`
	// Detail is what a built-in protects or what a pattern matches, whichever
	// the row is.
	Detail string `json:"detail,omitempty"`
}

// blockRows is the listing, declared entries first: they are what the
// operator wrote and what a converge acts on, and the built-in list is long
// enough to push them off a screen.
func blockRows(configDir string, declared []config.BlockedPath, builtIn bool) []blockRow {
	rows := make([]blockRow, 0, len(declared)+len(install.BuiltInRules()))
	for _, entry := range declared {
		if entry.Command != "" {
			rows = append(rows, blockRow{
				Source: sourceDeclared, Kind: kindCommand, Entry: entry.Command,
				Covers: coversCommands,
				Detail: "the agent's shell may not run it",
			})
			continue
		}
		if entry.Name != "" {
			rows = append(rows, blockRow{
				Source: sourceDeclared, Kind: install.BlockedNameKind(entry.Name),
				Entry: entry.Name, Covers: coversBoth,
				Detail: install.BlockedNameMatches(entry.Name),
			})
			continue
		}
		rows = append(rows, blockRow{
			Source: sourceDeclared, Kind: "path", Entry: entry.Path, Covers: coversBoth,
			State: blockedPathState(entry.Path),
		})
	}
	if !builtIn {
		return rows
	}
	// What this install occupies, which is refused without anybody declaring it
	// and is most of what a bare host blocks. Derived from the layout rather
	// than compiled in, so these are the paths this host actually uses.
	for _, dir := range install.InstalledDirs(configDir) {
		rows = append(rows, blockRow{
			Source: sourceBuiltIn, Kind: "dir", Entry: dir, Covers: coversBoth,
			Detail: "this install's own, and everything under it",
		})
	}
	for _, rule := range install.BuiltInRules() {
		rows = append(rows, blockRow{
			Source: sourceBuiltIn, Kind: rule.Kind, Entry: rule.Entry,
			Covers: coversBoth, Detail: rule.Why,
		})
	}
	// What faramir blocks for what a command does rather than for what it
	// names. No entry changes these, and nothing else can be asked what they
	// are.
	for _, pattern := range guard.ActionPatterns() {
		rows = append(rows, blockRow{
			Source: sourceBuiltIn, Kind: kindCommand, Entry: pattern, Covers: coversCommands,
		})
	}
	return rows
}

// blockedPathState is whether a declared path is there. The same state `link
// ls` carries, and for the same reason: it changes without anybody touching the
// config, and absent is not a fault here, a rule waiting for a volume being the
// point.
//
// "not there" means the path is not there, so a stat that failed for any other
// reason says so instead: this command needs no root, and a blocked path under
// a directory only root can enter would otherwise read as an entry waiting for
// a volume that is never coming.
func blockedPathState(path string) string {
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

// What a row is enforced at, in the words the column prints.
const (
	// kindCommand is the row kind for a rule about what a command does.
	kindCommand = "command"
	// sourceDeclared is a rule this host declared, as against one faramir carries.
	sourceDeclared = "declared"
	// sourceBuiltIn is a rule faramir carries or derives, as against one declared.
	sourceBuiltIn  = "built-in"
	coversBoth     = "file tools, commands"
	coversCommands = "commands"
)

func runBlockList(f blockFlags) int {
	dir := blockConfigDir(f)
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
	rows := blockRows(dir, declared, !f.declared)
	if f.json {
		// [] rather than null, for the reason `link ls` gives.
		if rows == nil {
			rows = []blockRow{}
		}
		body, marshalErr := json.MarshalIndent(rows, "", "  ")
		if marshalErr != nil {
			fmt.Fprintf(os.Stderr, "faramir block ls: %v\n", marshalErr)
			return 1
		}
		fmt.Println(string(body))
		return 0
	}
	if len(rows) == 0 {
		fmt.Fprintln(os.Stderr, "no [[secret.block]] entries; `faramir block ls` "+
			"without --declared lists the rules compiled in")
		return 0
	}
	// The command rules are printed under the table rather than in it: they are
	// regular expressions, one of them long enough that a cell holding it would
	// take the alignment of every other row with it, and they are read as
	// patterns rather than scanned as a column.
	var commands []blockRow
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "SOURCE\tKIND\tENTRY\tCOVERS")
	for _, row := range rows {
		if row.Kind == kindCommand {
			commands = append(commands, row)
			continue
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\n",
			row.Source, row.Kind, row.Entry, row.Covers)
	}
	_ = w.Flush()
	if len(commands) == 0 {
		return 0
	}
	fmt.Printf("\n%d command rule(s), which no entry changes: faramir blocks these "+
		"for what the command does rather than for what it names.\n", len(commands))
	for _, row := range commands {
		fmt.Printf("  %s\n", row.Entry)
	}
	return 0
}

// errReason is why a stat failed, in the few words a table cell has room for.
func errReason(err error) string {
	if errors.Is(err, os.ErrPermission) {
		return "no permission to look"
	}
	return "stat failed"
}

func blockOptions(f blockFlags) install.Options {
	return install.Options{
		ConfigDir: blockConfigDir(f),
		AgentUser: operatorName(f.agentUser),
		Log:       stepLog(f.json),
	}
}

func blockConfigDir(f blockFlags) string {
	return resolveConfigDir(f.configPath, socketDefault())
}
