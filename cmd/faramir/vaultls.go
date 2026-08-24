package main

// Listing the store, and taking a file out of it.
//
// `ls` is the operator's view and `refs` is the broker's. A managed file the
// broker refused to load is invisible to `refs`; `ls` reads the directory and
// sees it, which is the state an operator most needs named.

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	yaml "go.yaml.in/yaml/v3"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// opRemove is the audit record taking a file out of the store writes. It names
// the refs that went with it: the file is gone and the log is what is left of
// it.
const opRemove = "remove"

// managedFile is one file as `ls` reports it.
type managedFile struct {
	// Name is what an operator types, and Path is what is on disk. Both, so the
	// listing can be pasted into another command and read as a path.
	Name       string   `json:"name"`
	Path       string   `json:"path"`
	Refs       []string `json:"refs"`
	Recipients []string `json:"recipients"`
	// Drifted is true where the file is sealed to a set the rule no longer names,
	// which is what `faramir reader reseal` is for.
	Drifted bool `json:"drifted"`
	// Problem is why this file could not be read or parsed, and "" otherwise. A
	// file the broker would refuse is what an operator comes here to find, so it
	// is a row rather than a reason to stop.
	Problem string `json:"problem,omitempty"`
}

type vaultListFlags struct {
	json bool
	when string
}

func newVaultListCmd() *cobra.Command {
	var f vaultListFlags
	c := &cobra.Command{
		Use:   useLs,
		Short: "List the encrypted files, their refs and who can read them",
		Long: "Reads the secrets directory rather than asking the broker, so a file the\n" +
			"broker refused to load is listed here with the reason. `faramir refs` is\n" +
			"the other question: what the broker is serving.\n\n" +
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
	paint, err := newPalette(f.when)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 2
	}
	// The secrets directory is 2750 and the group is the keeper's, so the operator
	// cannot list it. Blocked with the reason rather than reported as an empty
	// store.
	if !requireRoot(label, "the secrets directory is readable only by the keeper and by root") {
		return 1
	}
	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	wanted, ruleErr := ruleRecipients(rulePath)

	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	files := make([]managedFile, 0, len(managed))
	for _, path := range managed {
		files = append(files, describeManaged(path, wanted, ruleErr == nil))
	}
	// By the name an operator types, which is not the order a glob returns once
	// the directory holds a name that sorts differently from its path.
	slices.SortFunc(files, func(a, b managedFile) int {
		return strings.Compare(a.Name, b.Name)
	})

	if f.json {
		out, err := json.MarshalIndent(files, "", "  ")
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}

	if len(files) == 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: no managed files\n", label)
	} else {
		// The directory once, above the rows, so the names are the ones the other
		// commands take and a full path is still readable.
		fmt.Println(paint.dim(filepath.Dir(cfg.Secret.Patterns[0])))
		table := [][]cell{{
			painted("NAME", paint.key), painted("REFS", paint.key),
			painted("READERS", paint.key), painted("STATE", paint.key),
		}}
		for _, file := range files {
			state, colour := stateOf(file), paint.ok
			switch {
			case file.Problem != "":
				colour = paint.bad
			case file.Drifted:
				colour = paint.warn
			}
			table = append(table, []cell{
				value(file.Name), painted(strconv.Itoa(len(file.Refs)), paint.ref),
				painted(strconv.Itoa(len(file.Recipients)), paint.dim),
				painted(state, colour),
			})
		}
		printTable(os.Stdout, table)
	}
	// Named after the listing rather than mixed into it: a pattern that matched
	// nothing is not a file.
	for _, reason := range slices.Concat(failures, absent) {
		fmt.Fprintf(os.Stderr, "faramir %s: not reached: %s\n", label, safe(reason))
	}
	if ruleErr != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, ruleErr)
	}
	return 0
}

// stateOf is the one word a listing has room for.
func stateOf(file managedFile) string {
	switch {
	case file.Problem != "":
		return file.Problem
	case file.Drifted:
		return "drifted"
	}
	return "ok"
}

// describeManaged reads one file without decrypting it: both the ref names and
// the recipients are cleartext in a sops file.
func describeManaged(path string, wanted []string, haveRule bool) managedFile {
	file := managedFile{Name: managedStem(path), Path: path}
	recipients, err := sopsrule.SealedTo(path)
	if err != nil {
		file.Problem = "not sealed to any age recipient"
		return file
	}
	file.Recipients = recipients
	file.Drifted = haveRule && !sopsrule.Same(recipients, wanted)

	refs, err := refsIn(path)
	if err != nil {
		file.Problem = err.Error()
		return file
	}
	file.Refs = refs
	return file
}

// refsIn is the refs a managed file names, taken from its structure rather than
// its values. sops encrypts values and leaves keys readable, so this answers
// without the age key: [keeper.Flatten] is given the file as it sits on disk,
// so each ref maps onto ciphertext and only the names are kept.
func refsIn(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var doc map[string]any
	if err := yaml.Unmarshal(body, &doc); err != nil {
		return nil, fmt.Errorf("does not parse: %w", err)
	}
	refs := make([]string, 0, len(doc))
	for ref := range keeper.Flatten(doc) {
		refs = append(refs, ref)
	}
	slices.Sort(refs)
	return refs, nil
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
		Long: "Deletes one managed file and every value in it. Only a backup brings\n" +
			"them back.\n\n" +
			"It names the refs it is about to destroy and asks for the file name back.\n" +
			"--force answers for you.",
		Args: exactlyArgs(1, "one file name"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runVaultRemove(f, args[0]))
		},
	}
	c.Flags().BoolVar(&f.force, "force", false,
		"do not ask; the file and every value in it go without confirmation")
	return c
}

func runVaultRemove(f vaultRemoveFlags, name string) int {
	const label = "vault rm"
	if !requireRoot(label, "the secrets directory is readable only by the keeper and by root") {
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
	target, err := resolveManaged(managed, name)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		for _, reason := range slices.Concat(failures, absent) {
			fmt.Fprintf(os.Stderr, "  %s\n", safe(reason))
		}
		return 1
	}

	// Read before anything is asked, so the question names what is at stake
	// rather than a path.
	refs, refsErr := refsIn(target)
	if !f.force && !confirmRemoval(target, refs, refsErr) {
		fmt.Fprintf(os.Stderr, "faramir %s: left %s alone\n", label, safe(target))
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
	stopped := reReadNote(tellBrokerToReRead(),
		"it stops serving them within one refresh interval")
	if strings.HasPrefix(stopped, "the broker has re-read") {
		stopped = "the broker has stopped serving them"
	}
	fmt.Fprintf(os.Stderr, "faramir %s: removed %s and the %d ref(s) it held; %s\n",
		label, safe(target), len(refs), stopped)
	return 0
}

// confirmRemoval puts the question to whoever is at the terminal, and takes
// only the file's own name for an answer: a y/n prompt is answered by reflex.
// Deny by default, so a closed stdin or an empty line is a no.
func confirmRemoval(target string, refs []string, refsErr error) bool {
	fmt.Fprintf(os.Stderr, "%s\n", safe(target))
	switch {
	case refsErr != nil:
		fmt.Fprintf(os.Stderr, "  its refs could not be read (%v), so what goes with "+
			"it is not known here\n", refsErr)
	case len(refs) == 0:
		fmt.Fprintf(os.Stderr, "  it names no ref\n")
	default:
		fmt.Fprintf(os.Stderr, "  %d ref(s) go with it: %s\n", len(refs), safe(strings.Join(refs, ", ")))
	}
	// The expected word is shown rather than guessed at: what makes this safe is
	// having read which file it is, not having worked out what to type.
	name := managedStem(target)
	fmt.Fprintf(os.Stderr, "Every value in it is destroyed, and nothing here brings "+
		"it back.\nType %s to remove it: ", safe(name))
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		fmt.Fprintln(os.Stderr)
		return false
	}
	// Either spelling, the short one being what was typed to get here and the
	// full one what is on disk.
	answer := strings.TrimSpace(line)
	return answer == name || answer == filepath.Base(target)
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
		GroupID: groupOperator,
		Long: "Each name is a ref: what `--env NAME=faramir://<ref>` and `env_refs`\n" +
			"take.\n\n" +
			"Asks the broker, so this is what a brokered command could name.\n" +
			"`faramir vault ls` is the other question: what is in the directory.\n\n" +
			"Needs no root. Names only, never a value.",
		Args: noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(send("refs", socketDefault(), map[string]any{"op": "refs"},
				o.json, true))
		},
	}
	o.add(c)
	return c
}
