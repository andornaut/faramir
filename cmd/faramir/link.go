package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"text/tabwriter"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/secretlink"
)

// newLinkCmd groups what is done to a linked secret: one a tool of yours owns,
// read where that tool keeps it rather than copied into the managed store.
//
// The store's own commands are `faramir vault`. Two nouns rather than one, and
// deliberately: what they share is a ref namespace, not a mechanism.
func newLinkCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "link",
		Short:   "Manage secrets read out of files another tool maintains",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newLinkAddCmd(), newLinkRemoveCmd(), newLinkListCmd())
	return c
}

type linkFlags struct {
	configPath string
	agentUser  string
	kind       string
	key        string
	json       bool
}

func (f *linkFlags) register(c *cobra.Command) {
	fl := c.Flags()
	// A directory, not a file: everything below joins config.toml onto it, and
	// the other provisioning commands that take one spell it this way.
	fl.StringVar(&f.configPath, "config-dir", "",
		"the install to act on (default: where the running broker says it is)")
	fl.StringVar(&f.agentUser, "agent-user", "",
		"account the coding agent runs as (default $SUDO_USER, then you)")
}

func newLinkAddCmd() *cobra.Command {
	var f linkFlags
	c := &cobra.Command{
		Use:   "add [options] REF FILE",
		Short: "Read a secret out of a file another tool maintains",
		Long: "Adds one [[secret.link]] entry and applies everything that follows: the\n" +
			"broker's account is granted read on the file, the file is refused to the\n" +
			"agent's file tools, and the daemons are reloaded.\n\n" +
			"The file is read once, as the broker's own account, before anything is\n" +
			"written. A selector that names nothing is an error here rather than a\n" +
			"broker refusing every command later.\n\n" +
			"Adding the entry this install already carries re-applies it: the grant\n" +
			"comes back where a tool took it away by renaming its own file, and so does\n" +
			"a rule an agent's settings dropped. Nothing is written that was not there,\n" +
			"and --json reports changed=false. The same ref against a different file,\n" +
			"type or key is an error: a ref has one definition.",
		Args: exactlyArgs(2, "a ref and a file"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runLinkAdd(f, args[0], args[1]))
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
	link := config.Link{Ref: ref, Path: path, Type: f.kind, Key: f.key}
	report, added, err := install.AddLink(installOptions(f), link)
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
	// under whatever brokered command is running. One that regranted a lost
	// access does need it: the broker fingerprints a linked file by mtime and
	// size, which a chgrp leaves alone, so it would go on refusing every command
	// against a file it can now read.
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
		Short: "Stop reading a linked secret",
		Long: "Removes the entry, so the value leaves the redactor and stops being\n" +
			"injectable.\n\n" +
			"Two things it does not undo. The deny rule stays: the agent rule files are\n" +
			"merged rather than replaced, and a merge can only add, so nothing here can\n" +
			"take an entry out of one. The access granted to the broker stays too: this\n" +
			"does not know the mode the file had before, and guessing at one is as\n" +
			"likely to break the tool that owns it. Both are printed, with what would\n" +
			"undo them.\n\n" +
			"A ref this install does not carry is not an error: nothing is written and\n" +
			"--json reports changed=false, the entry being gone either way.",
		Args: exactlyOneArg("ref"),
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runLinkRemove(f, args[0])) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the report as JSON")
	return c
}

func runLinkRemove(f linkFlags, ref string) int {
	if !requireRoot("link rm", "it writes the config") {
		return 1
	}
	report, removed, err := install.RemoveLink(installOptions(f), ref)
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
		Short: "List the linked secrets this install declares",
		Args:  noArgs,
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runLinkList(f)) },
	}
	f.register(c)
	c.Flags().BoolVar(&f.json, "json", false, "print the entries as JSON")
	return c
}

func runLinkList(f linkFlags) int {
	dir := installConfigDir(f)
	links, err := install.Links(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir link ls: %v\n", err)
		return 1
	}
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
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	_, _ = fmt.Fprintln(w, "REF\tTYPE\tKEY\tFILE\tSTATE")
	for _, link := range links {
		state := "present"
		if _, err := os.Stat(link.Path); err != nil {
			state = "not there"
		}
		key := link.Key
		if key == "" {
			key = "-"
		}
		_, _ = fmt.Fprintf(w, "%s\t%s\t%s\t%s\t%s\n", link.Ref, link.Type, key, link.Path, state)
	}
	_ = w.Flush()
	return 0
}

// installOptions is the install this command acts on. The config path resolves
// the way every provisioning command's does, by asking a running broker where
// the install is when no flag names it.
func installOptions(f linkFlags) install.Options {
	return install.Options{
		ConfigDir: installConfigDir(f),
		AgentUser: operatorName(f.agentUser),
		// Progress goes to stderr so --json owns stdout, and is suppressed under
		// --json entirely, as `init` suppresses it: the steps are in the document.
		Log: stepLog(f.json),
	}
}

// stepLog is where a run's per-step lines go: stderr, or nowhere under --json.
func stepLog(asJSON bool) func(string) {
	if asJSON {
		return nil
	}
	return func(line string) { fmt.Fprintln(os.Stderr, line) }
}

func installConfigDir(f linkFlags) string {
	return resolveConfigDir(f.configPath, socketDefault())
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
