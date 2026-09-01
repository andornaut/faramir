package main

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/termui"
)

// newLinkCmd groups what is done to a linked secret: one a tool of yours owns,
// read where that tool keeps it rather than copied into the managed store.
//
// The store's own commands are `faramir vault`. Two nouns rather than one, and
// deliberately: what they share is a ref namespace, not a mechanism.
func newLinkCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "link",
		Short:   "Manage secrets read from files another tool maintains",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newLinkAddCmd(), newLinkRemoveCmd(), newLinkListCmd())
	return c
}

type linkFlags struct {
	kind string
	key  string
	json bool
	when string
	// strict refuses every command naming the file, not only the ones that
	// would read it. On add alone: rm takes the entry out either way.
	strict bool
	// verbose prints the file-by-file account of what was written. See stepLog.
	verbose bool
}

func newLinkAddCmd() *cobra.Command {
	var f linkFlags
	c := &cobra.Command{
		Use:   "add [options] REF FILE",
		Short: "Add a secret read from a file another tool maintains",
		Long: "Adds one [[secret.link]] entry and applies it: the broker is granted read\n" +
			"on the file, the file is refused to the agent's file tools, and the daemons\n" +
			"are reloaded.\n\n" +
			"REF is the name a caller asks by, with or without the faramir:// that\n" +
			"`faramir refs` prints it with.\n\n" +
			"The file is read once, as the broker, before anything is written, so a\n" +
			"selector naming nothing is an error here rather than later.\n\n" +
			"Re-adding the same entry re-applies it, which is what restores a grant or\n" +
			"a rule something took away, and reports changed=false. The same ref\n" +
			"against a different file, type or key is an error; against a different\n" +
			"--strict it changes the entry, that being how strictly one rule is\n" +
			"matched rather than a second rule.\n\n" +
			"Prints the ref it added and nothing else. --verbose adds the file-by-file\n" +
			"account of what was written.",
		Args: exactlyArgs(2, "a ref and a file"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runLinkAdd(f, secretref.Bare(args[0]), args[1]))
		},
	}
	c.Flags().StringVar(&f.kind, "type", "",
		"how to read the file: "+strings.Join(secretlink.Kinds(), ", "))
	c.Flags().StringVar(&f.key, "key", "",
		"what to select out of it, for the types that select")
	c.Flags().BoolVar(&f.strict, "strict", false,
		"refuse every command NAMING this file, not only the ones that would "+
			"print it: ls, stat, chmod and mv included. Ask for the ref "+
			"instead. Off by default, since a file nothing may touch is a file its own "+
			"tool cannot be told to rewrite either")
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	c.Flags().BoolVar(&f.verbose, "verbose", false, "also print every file this changed")
	return c
}

func runLinkAdd(f linkFlags, ref, path string) int {
	if !requireRoot("link add", "it writes the config and regroups a file") {
		return 1
	}
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link add: %v\n", err)
		return 1
	}
	link := config.Link{Ref: ref, Path: path, Type: f.kind, Key: f.key,
		Strict: f.strict}
	report, added, err := install.AddLink(installOptions(f, dir), link)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link add: %v\n", err)
	}
	if code := reportDocument(f.json, "link add", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	// Reloaded here rather than left to the operator: the daemons read the config
	// once at startup, so an entry written and not reloaded is a link that exists
	// in the file and in nothing else.
	//
	// Only when something changed. A re-assert that found the host as it should
	// be has nothing new for a daemon to read, and reloading would restart them
	// under whatever brokered command is running.
	//
	// A run that reported a linked file needing repair changes nothing either,
	// this command not altering a file it does not own, so it does not reload.
	// The broker fingerprints a linked file by mtime and size and a chgrp changes
	// neither, so a repair is followed by a restart the operator makes; `faramir
	// doctor` says so where it reports one.
	if report.Changed {
		if err := install.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "faramir link add: applied %s, but the daemons did not "+
				"reload, so it is not being served yet: %v\n", ref, err)
			return 1
		}
	}
	if f.json {
		return 0
	}
	if added {
		fmt.Fprintf(os.Stderr, "added %s\n", ref)
		printWarnings(report)
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s already reads %s, so nothing was added; its grant and "+
		"the rules naming it were applied again\n", ref, path)
	printWarnings(report)
	return 0
}

func newLinkRemoveCmd() *cobra.Command {
	var f linkFlags
	c := &cobra.Command{
		Use:   "rm [options] REF",
		Short: "Remove a linked secret",
		Long: "Removes the entry, so the value leaves the redactor and stops being\n" +
			"injectable.\n\n" +
			"The rules faramir wrote into your agent's settings go with it, against\n" +
			"the record of what it last wrote there; a rule you added yourself naming\n" +
			"the same path is not in that record and stays.\n\n" +
			"One thing it does not undo: the read granted to the broker, whose previous\n" +
			"mode this does not know. It is printed with what undoes it.\n\n" +
			"Prints the ref it removed and nothing else. --verbose adds the\n" +
			"file-by-file account of what was written.\n\n" +
			"A ref this install does not carry reports changed=false.",
		Args: exactlyOneArg("ref"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runLinkRemove(f, secretref.Bare(args[0])))
		},
	}
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	c.Flags().BoolVar(&f.verbose, "verbose", false, "also print every file this changed")
	return c
}

func runLinkRemove(f linkFlags, ref string) int {
	if !requireRoot("link rm", "it writes the config") {
		return 1
	}
	dir, err := resolveConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link rm: %v\n", err)
		return 1
	}
	report, removed, err := install.RemoveLink(installOptions(f, dir), ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link rm: %v\n", err)
	}
	if code := reportDocument(f.json, "link rm", report); code != 0 {
		return code
	}
	if err != nil {
		return 1
	}
	// Only what changed reaches a daemon, as in link add.
	if report.Changed {
		if err := install.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "faramir link rm: removed %s, but the daemons did not "+
				"reload, so it is still being served: %v\n", ref, err)
			return 1
		}
	}
	if f.json {
		return 0
	}
	if removed.Ref == "" {
		fmt.Fprintf(os.Stderr, "no link named %s, so nothing was removed; "+
			"`faramir link ls` lists the ones there are\n", ref)
		printWarnings(report)
		return 0
	}
	fmt.Fprintf(os.Stderr, "removed %s\n", removed.Ref)
	printWarnings(report)
	// What was granted and is still granted, so the operator decides rather than
	// discovering it later.
	fmt.Fprintf(os.Stderr, "%s is still readable by the broker's group; narrow it "+
		"with: chmod g-r %s\n", removed.Path, removed.Path)
	// Only where an agent's settings were actually rewritten; see runBlockRemove.
	if changedAny(report, "agent config", "enrolled trees") {
		fmt.Fprintln(os.Stderr, "a rule you added to your agent's settings yourself, "+
			"naming the same path, is not in faramir's record of what it wrote there "+
			"and stays; take that line out yourself")
	}
	return 0
}

func newLinkListCmd() *cobra.Command {
	var f linkFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List the linked secrets",
		Args:  noArgs,
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runLinkList(f)) },
	}
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	addColorFlag(c, &f.when)
	return c
}

func runLinkList(f linkFlags) int {
	paint, bad := termui.PaletteFor("link ls", f.when)
	if bad != 0 {
		return bad
	}
	dir, err := installedConfigDir(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link ls: %v\n", err)
		return 1
	}
	links, err := install.Links(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link ls: %v\n", err)
		return 1
	}
	// By ref, so a listing is the same twice running and two hosts diff against
	// each other. Config order is whatever they were added in, which is a
	// history rather than an order anybody reads by.
	slices.SortFunc(links, func(a, b config.Link) int {
		return strings.Compare(a.Ref, b.Ref)
	})
	if f.json {
		// An empty install prints [], not null: a nil slice marshals to null, and a
		// caller iterating the document would break on the one answer it is most
		// likely to get from a host that declares none.
		if links == nil {
			links = []config.Link{}
		}
		return printJSON("link ls", links)
	}
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "no linked secrets")
		return 0
	}
	// Whether the file is there, which is the state that changes without anybody
	// touching the config: a credential removed, or a home not mounted. Whether
	// the broker can read it is doctor's question, that one needing to be asked as
	// the broker.
	table := [][]termui.Cell{{
		termui.Painted("REF", paint.Key), termui.Painted("TYPE", paint.Key),
		termui.Painted("KEY", paint.Key), termui.Painted("FILE", paint.Key),
		termui.Painted("STATE", paint.Key),
	}}
	for _, link := range links {
		state, colour := "present", paint.OK
		if _, err := os.Stat(link.Path); err != nil {
			state, colour = "not there", paint.Bad
		}
		key := link.Key
		if key == "" {
			key = "-"
		}
		// The ref takes the colour `faramir logs` gives one, the two listings
		// being read by the same operator. The path and the key are the
		// operator's own and stay unpainted.
		table = append(table, []termui.Cell{
			termui.Painted(link.Ref, paint.Ref), termui.Painted(link.Type, paint.Dim),
			termui.Value(key), termui.Value(link.Path), termui.Painted(state, colour),
		})
	}
	termui.PrintTable(os.Stdout, table)
	return 0
}

// installOptions is the install this command acts on, at the directory the
// caller has already resolved.
func installOptions(f linkFlags, dir string) install.Options {
	return install.Options{
		ConfigDir: dir,
		// What [server] agent_user records, for the reason recordedOperator gives:
		// these re-render the agent's rule files, and the account those are
		// rendered against is not theirs to choose.
		AgentUser: recordedOperator(filepath.Join(dir, "config.toml")),
		// Progress goes to stderr so --json owns stdout. See stepLog for when.
		Log: stepLog(f.json, f.verbose),
	}
}

// stepLog is where a run's per-step lines go: stderr under --verbose, and
// nowhere otherwise.
//
// Off by default because these commands are asked one question -- did the thing
// I named happen -- and a dozen lines naming every file written are a dozen
// lines to read before the answer. Nowhere under --json either, as `init`
// suppresses them: the steps are in the document.
func stepLog(asJSON, verbose bool) func(string) {
	if asJSON || !verbose {
		return nil
	}
	return func(line string) { fmt.Fprintln(os.Stderr, line) }
}

// reportDocument prints the whole report under --json and nothing otherwise. A
// non-zero return is a document that would not marshal, which is fatal on its
// own.
//
// Shared by `link` and `block`, their reports being the same document and their
// callers the same shape.
func reportDocument(asJSON bool, label string, report install.Report) int {
	if !asJSON {
		return 0
	}
	return printJSON(label, report)
}

// printWarnings puts a run's warnings out, and is called after the outcome
// rather than before it: each one is about a file, and a warning read ahead of
// the outcome is read as the outcome.
func printWarnings(report install.Report) {
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
}
