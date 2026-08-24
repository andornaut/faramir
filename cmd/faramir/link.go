package main

import (
	"encoding/json"
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
	agentUser string
	kind      string
	key       string
	json      bool
	when      string
}

func (f *linkFlags) register(c *cobra.Command) {
	fl := c.Flags()
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as. Defaults to what [server] agent_user "+
			"records, and naming a different one is refused: 'faramir init "+
			"--agent-user' is what changes who the host belongs to")
}

// registerUnread is the flag on the listing, for the reason `block ls` gives.
func (f *linkFlags) registerUnread(c *cobra.Command) {
	c.Flags().StringVar(&f.agentUser, "agent-user", "",
		"accepted so it can be passed to every subcommand alike, and not read "+
			"here: a listing renders no rule files, so it resolves no operator")
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
			"against a different file, type or key is an error.",
		Args: exactlyArgs(2, "a ref and a file"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runLinkAdd(f, secretref.Bare(args[0]), args[1]))
		},
	}
	f.register(c)
	c.Flags().StringVar(&f.kind, "type", "",
		"how to read the file: "+strings.Join(secretlink.Kinds(), ", "))
	c.Flags().StringVar(&f.key, "key", "",
		"what to select out of it, for the types that select")
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
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
	link := config.Link{Ref: ref, Path: path, Type: f.kind, Key: f.key}
	opts, err := installOptions(f, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link add: %v\n", err)
		return 2
	}
	report, added, err := install.AddLink(opts, link)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link add: %v\n", err)
	}
	if code := reportEntry(f.json, "link add", report); code != 0 {
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
		return 0
	}
	fmt.Fprintf(os.Stderr, "%s already reads %s, so nothing was added; its grant and "+
		"the rules naming it were applied again\n", ref, path)
	return 0
}

func newLinkRemoveCmd() *cobra.Command {
	var f linkFlags
	c := &cobra.Command{
		Use:   "rm [options] REF",
		Short: "Remove a linked secret",
		Long: "Removes the entry, so the value leaves the redactor and stops being\n" +
			"injectable.\n\n" +
			"Two things it does not undo: the deny rule in the agent's settings, which\n" +
			"are merged rather than replaced, and the read granted to the broker, whose\n" +
			"previous mode this does not know. Both are printed with what undoes them.\n\n" +
			"A ref this install does not carry reports changed=false.",
		Args: exactlyOneArg("ref"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runLinkRemove(f, secretref.Bare(args[0])))
		},
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
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
	opts, err := installOptions(f, dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link rm: %v\n", err)
		return 2
	}
	report, removed, err := install.RemoveLink(opts, ref)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link rm: %v\n", err)
	}
	if code := reportEntry(f.json, "link rm", report); code != 0 {
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
		return 0
	}
	// What was granted and is still granted, so the operator decides rather than
	// discovering it later.
	fmt.Fprintf(os.Stderr, "removed %s\n", removed.Ref)
	fmt.Fprintf(os.Stderr, "%s is still readable by the broker's group; narrow it "+
		"with: chmod g-r %s\n", removed.Path, removed.Path)
	fmt.Fprintf(os.Stderr, "the deny rule naming it stays in your agent's settings: "+
		"a merged rule file carries no sign of who added an entry, so nothing "+
		"removes one for you\n")
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
	f.registerUnread(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	addColorFlag(c, &f.when)
	return c
}

func runLinkList(f linkFlags) int {
	paint, err := newPalette(f.when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link ls: %v\n", err)
		return 2
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
		body, err := json.MarshalIndent(links, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir link ls: %v\n", err)
			return 1
		}
		fmt.Println(string(body))
		return 0
	}
	if len(links) == 0 {
		fmt.Fprintln(os.Stderr, "no linked secrets")
		return 0
	}
	// Whether the file is there, which is the state that changes without anybody
	// touching the config: a credential removed, or a home not mounted. Whether
	// the broker can read it is doctor's question, that one needing to be asked as
	// the broker.
	table := [][]cell{{
		painted("REF", paint.key), painted("TYPE", paint.key),
		painted("KEY", paint.key), painted("FILE", paint.key),
		painted("STATE", paint.key),
	}}
	for _, link := range links {
		state, colour := "present", paint.ok
		if _, err := os.Stat(link.Path); err != nil {
			state, colour = "not there", paint.bad
		}
		key := link.Key
		if key == "" {
			key = "-"
		}
		// The ref takes the colour `faramir logs` gives one, the two listings
		// being read by the same operator. The path and the key are the
		// operator's own and stay unpainted.
		table = append(table, []cell{
			painted(link.Ref, paint.ref), painted(link.Type, paint.dim),
			value(key), value(link.Path), painted(state, colour),
		})
	}
	printTable(os.Stdout, table)
	return 0
}

// installOptions is the install this command acts on, at the directory the
// caller has already resolved.
func installOptions(f linkFlags, dir string) (install.Options, error) {
	// The recorded agent_user ahead of everything, for the reason recordedOperator
	// gives: these commands re-render the agent's rule files, and the account
	// those rules are rendered against is not theirs to choose.
	operator, err := recordedOperator(filepath.Join(dir, "config.toml"), f.agentUser)
	if err != nil {
		return install.Options{}, err
	}
	return install.Options{
		ConfigDir: dir,
		AgentUser: operator,
		// Progress goes to stderr so --json owns stdout, and is suppressed under
		// --json entirely, as `init` suppresses it: the steps are in the document.
		Log: stepLog(f.json),
	}, nil
}

// stepLog is where a run's per-step lines go: stderr, or nowhere under --json.
func stepLog(asJSON bool) func(string) {
	if asJSON {
		return nil
	}
	return func(line string) { fmt.Fprintln(os.Stderr, line) }
}

// reportEntry is how `link` and `refuse` report an add or a remove: the whole
// document under --json, and otherwise the warnings alone, the steps having
// already been logged as they ran. A non-zero return is a document that would
// not marshal, which is fatal on its own.
//
// Shared by the two commands, their reports being the same document and their
// callers the same shape.
func reportEntry(asJSON bool, label string, report install.Report) int {
	if asJSON {
		return printJSON(label, report)
	}
	for _, warning := range report.Warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}
	return 0
}
