package main

// Listing the store, and taking a file out of it.
//
// `ls` is the operator's view and `refs` is the broker's. A managed file the
// broker refused to load is invisible to `refs`; `ls` reads the directory and
// sees it, which is the state an operator most needs named.

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/termui"
	"github.com/andornaut/faramir/internal/vault"
)

// opRemove is the audit record taking a file out of the store writes. It names
// the refs that went with it: the file is gone and the log is what is left of
// it.
const opRemove = "remove"

type vaultListFlags struct {
	json bool
	when string
}

func newVaultListCmd() *cobra.Command {
	var f vaultListFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List the encrypted files, their refs and who can read them",
		Long: "Reads the secrets directory directly, so a file the broker refused to\n" +
			"load is listed here with the reason. `faramir refs` lists what the broker\n" +
			"is serving.\n\n" +
			"Ref names are cleartext in a sops file, so this decrypts nothing.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runVaultList(f)) },
	}
	c.Flags().BoolVar(&f.json, "json", false, "print the listing as JSON")
	addColorFlag(c, &f.when)
	return c
}

func runVaultList(f vaultListFlags) int {
	const label = "vault ls"
	paint, bad := termui.PaletteFor(label, f.when)
	if bad != 0 {
		return bad
	}
	// The secrets directory is 2750 and the group is the keeper's, so the operator
	// cannot list it. Blocked with the reason rather than reported as an empty
	// store.
	if !requireRoot(label) {
		return 1
	}
	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	wanted, ruleErr := vault.RuleRecipients(rulePath)

	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	files := make([]vault.ManagedFile, 0, len(managed))
	for _, path := range managed {
		files = append(files, vault.DescribeManaged(path, wanted, ruleErr == nil))
	}
	// By the name an operator types, which is not the order a glob returns once
	// the directory holds a name that sorts differently from its path.
	slices.SortFunc(files, func(a, b vault.ManagedFile) int {
		return strings.Compare(a.Name, b.Name)
	})

	if f.json {
		return printJSON(label, files)
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: no managed files\n", label)
	} else {
		// The directory once, above the rows, so the names are the ones the other
		// commands take and a full path is still readable.
		fmt.Println(paint.Dim(filepath.Dir(cfg.Secret.Patterns[0])))
		table := [][]termui.Cell{{
			termui.Painted("NAME", paint.Key), termui.Painted("REFS", paint.Key),
			termui.Painted("READERS", paint.Key), termui.Painted("STATE", paint.Key),
		}}
		for _, file := range files {
			state, colour := vault.StateOf(file), paint.OK
			switch {
			case file.Problem != "":
				colour = paint.Bad
			case file.Drifted:
				colour = paint.Warn
			}
			table = append(table, []termui.Cell{
				termui.Value(file.Name), termui.Painted(strconv.Itoa(len(file.Refs)), paint.Ref),
				termui.Painted(strconv.Itoa(len(file.Recipients)), paint.Dim),
				termui.Painted(state, colour),
			})
		}
		termui.PrintTable(os.Stdout, table)
	}
	// Named after the listing rather than mixed into it: a pattern that matched
	// nothing is not a file.
	for _, reason := range slices.Concat(failures, absent) {
		fmt.Fprintf(os.Stderr, "faramir %s: not reached: %s\n", label, termui.Safe(reason))
	}
	if ruleErr != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, ruleErr)
	}
	return 0
}

type vaultRemoveFlags struct {
	force bool
}

func newVaultRemoveCmd() *cobra.Command {
	var f vaultRemoveFlags
	c := &cobra.Command{
		Use:     "rm [options] NAME",
		Aliases: []string{opRemove},
		Short:   "Remove an encrypted secret file",
		Long: "Deletes one managed file and every value in it. Only a backup can\n" +
			"restore them.\n\n" +
			"It lists the refs it is about to delete and asks for confirmation.\n" +
			"--force skips the question.",
		Args: exactlyArgs(1, "one file name"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runVaultRemove(f, args[0]))
		},
	}
	c.Flags().BoolVar(&f.force, "force", false,
		"delete the file and every value in it without asking")
	return c
}

func runVaultRemove(f vaultRemoveFlags, name string) int {
	const label = "vault rm"
	if !requireRoot(label) {
		return 1
	}
	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Resolved against the managed list, so this cannot delete a file the broker
	// never read.
	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	target, err := vault.Resolve(managed, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		for _, reason := range slices.Concat(failures, absent) {
			fmt.Fprintf(os.Stderr, "  %s\n", termui.Safe(reason))
		}
		return 1
	}

	// Read before anything is asked, so the question names what is at stake
	// rather than a path.
	refs, refsErr := vault.RefsIn(target)
	if !f.force && !confirmRemoval(target, refs, refsErr) {
		fmt.Fprintf(os.Stderr, "faramir %s: left %s alone\n", label, termui.Safe(target))
		return 1
	}

	err = os.Remove(target)
	// Written whether or not the removal worked, and naming the refs: the file is
	// gone and this record is what is left of what was in it.
	record := map[string]any{
		"op": opRemove, "log_id": audit.NewLogID(), "file": target, "refs": refs,
		"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
	}
	if err != nil {
		record["error"] = err.Error()
	}
	audit.NewLog(cfg.Audit).Write(record, audit.Output{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	stopped := reReadNote(brokerclient.Refresh(socketDefault()),
		"it stops serving them within one refresh interval")
	if strings.HasPrefix(stopped, "the broker has re-read") {
		stopped = "the broker has stopped serving them"
	}
	fmt.Fprintf(os.Stderr, "faramir %s: removed %s and the %d ref(s) it held; %s\n",
		label, termui.Safe(target), len(refs), stopped)
	return 0
}

// confirmRemoval puts the question to whoever is at the terminal, and takes the
// same answer an escalation does: termui.Approves, so one y and nothing else,
// preceded by the same termui.FlushTypeahead. Deny by default, so a closed stdin, an
// empty line or a typo is a no. What the question is worth comes from the lines
// above it, which name the file and every ref that goes with it.
func confirmRemoval(target string, refs []string, refsErr error) bool {
	fmt.Fprintf(os.Stderr, "%s\n", termui.Safe(target))
	switch {
	case refsErr != nil:
		fmt.Fprintf(os.Stderr, "  its refs could not be read: %v\n", refsErr)
	case len(refs) == 0:
		fmt.Fprintf(os.Stderr, "  it names no ref\n")
	default:
		fmt.Fprintf(os.Stderr, "  %d ref(s) will be deleted with it: %s\n", len(refs), termui.Safe(strings.Join(refs, ", ")))
	}
	// One keystroke answers this, so what was typed before the question was put
	// must not be able to spell the answer to it. The same flush an escalation
	// does, and for the same reason.
	termui.FlushTypeahead()
	fmt.Fprint(os.Stderr, "Remove? [y/n] ")
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr)
		return false
	}
	return termui.Approves(line)
}

// newRefsCmd is what the broker is serving, which is not the same question as
// what is in the directory. Top level rather than under `vault`, beside `run`,
// `redact` and `status`: it is one of the four an agent may run, and a group
// split across the two would need the deny rule to carve one leaf out by
// name.
func newRefsCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     "refs [options]",
		Short:   "List the secret names you can inject; values are never shown",
		GroupID: groupAgent,
		Long: "Asks the broker for the refs it serves, so this lists what a brokered\n" +
			"command can name. `faramir vault ls` lists what is in the secrets directory.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(send("refs", socketDefault(), map[string]any{"op": "refs"},
				o.json, true))
		},
	}
	o.add(c)
	return c
}
