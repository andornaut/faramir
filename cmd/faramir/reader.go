package main

// `faramir reader` manages who can decrypt the managed store: the rule and
// the ciphertext together, in one command. Editing `.sops.yaml` on its own
// leaves a state nothing reports -- a rule naming a reader the existing files
// are not sealed to -- which surfaces whenever somebody reaches for a value
// with a key they were told they had.
//
// So the rule is written and the store re-encrypted by the same command, and
// the rule is judged before it is written. `reseal` stays for what this cannot
// cover: a run that reached only some of the files, and a file edited by
// hand.

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/keygen"
	"github.com/andornaut/faramir/internal/termui"
	"github.com/andornaut/faramir/internal/vault"
)

// opReader is the audit record a rule change writes, one per command: the
// per-file records are the reseal's own, and what this adds is who the store is
// now readable by and who asked for that.
const opReader = "reader"

// newReaderCmd is a group spelled like `link add|rm|ls`. The guard names a
// subcommand by every token a person types, so the three here are three lines
// in cli.Operator, held against the command tree by a test.
func newReaderCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "reader",
		Short:   "Manage which keys can decrypt the secret files",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newReaderAddCmd(), newReaderRemoveCmd(), newReaderListCmd(),
		newReaderResealCmd())
	return c
}

type readerFlags struct {
	dryRun bool
	json   bool
	when   string
}

func (f *readerFlags) register(c *cobra.Command, writes bool) {
	fl := c.Flags()
	if !writes {
		fl.BoolVar(&f.json, "json", false, "print the recipients as JSON")
		addColorFlag(c, &f.when)
		return
	}
	fl.BoolVar(&f.dryRun, "dry-run", false,
		"report the rule change and the files that would be re-encrypted, and write nothing")
}

func newReaderAddCmd() *cobra.Command {
	var f readerFlags
	c := &cobra.Command{
		Use:   "add [options] KEY",
		Short: "Add a key that can decrypt the secret files",
		Long: "Adds an age recipient to .sops.yaml and re-encrypts every managed file to\n" +
			"it, so the rule and the ciphertext always agree.\n\n" +
			"KEY is a public key: age1... or an ssh public key. A private key is\n" +
			"refused, because .sops.yaml is world-readable. Create one with\n" +
			"'age-keygen -o FILE' on the machine that will hold it.",
		Args: exactlyArgs(1, "one age recipient"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runReaderChange(f, args[0], true))
		},
	}
	f.register(c, true)
	return c
}

func newReaderRemoveCmd() *cobra.Command {
	var f readerFlags
	c := &cobra.Command{
		Use:     "rm [options] KEY",
		Aliases: []string{opRemove},
		Short:   "Remove a key, so it can no longer decrypt the secret files",
		Long: "Removes an age recipient from .sops.yaml and re-encrypts every managed\n" +
			"file without it.\n\n" +
			"Copies of the old ciphertext can still be decrypted by that key. Treat\n" +
			"every value it could read as disclosed, and rotate them.",
		Args: exactlyArgs(1, "one age recipient"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runReaderChange(f, args[0], false))
		},
	}
	f.register(c, true)
	return c
}

func newReaderListCmd() *cobra.Command {
	var f readerFlags
	c := &cobra.Command{
		Use:     useLs,
		Aliases: []string{"list"},
		Short:   "List the keys that can decrypt the secret files",
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runReaderList(f)) },
	}
	f.register(c, false)
	return c
}

func newReaderResealCmd() *cobra.Command {
	var f readerFlags
	c := &cobra.Command{
		Use:   "reseal [options] [FILE...]",
		Short: "Re-encrypt every file to the keys .sops.yaml names",
		Long: "Re-encrypts the managed files to match .sops.yaml. Use it after editing\n" +
			".sops.yaml by hand, or after an `add` or `rm` that failed partway.\n\n" +
			"Every managed file is re-encrypted unless FILEs are named. Files already\n" +
			"encrypted to the current rule are skipped.",
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runReseal(f, args)) },
	}
	f.register(c, true)
	return c
}

// runReseal is a recipient change with no recipient: the rule is taken as it
// stands and the store is brought to it.
func runReseal(f readerFlags, args []string) int {
	const label = "reader reseal"
	store, code := loadStore(label, socketDefault(), args, false)
	if store == nil {
		return code
	}
	wanted, err := vault.RuleRecipients(store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Checked before anything is decrypted: re-encrypting to a rule the keeper is
	// not named in produces a secrets directory that opens for nobody the broker
	// can ask, one file at a time.
	if err := vault.KeeperStaysAReader(store.keyPath, wanted, store.rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	return resealStore(label, store, wanted, f.dryRun)
}

// runReaderChange is add and rm, which differ only in the edit they ask for.
// The order is the point: validate, edit in memory, judge the result, and only
// then write, so a rule that would leave the keeper out is one the file never
// comes to hold.
func runReaderChange(f readerFlags, recipient string, adding bool) int {
	label := "reader rm"
	if adding {
		label = "reader add"
		// Before root and before the config: a typo in a public key should not need
		// sudo to find out about.
		if err := keygen.ValidateRecipient(recipient); err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
	}

	store, code := loadStore(label, socketDefault(), nil, true)
	if store == nil {
		return code
	}
	// Named here rather than left to keeperStaysAReader below, whose advice is to
	// put the key back under `- age:`: to an operator who has just asked to
	// remove it, that reads as an instruction to undo what they typed.
	if !adding {
		if keeper, err := keygen.AgeRecipient(store.keyPath); err == nil && keeper == recipient {
			fmt.Fprintf(os.Stderr, "faramir %s: %s is the key %s decrypts with, and is "+
				"the one recipient this will not remove: without it nothing on this host "+
				"can open the store\n", label, recipient, store.keyPath)
			return 1
		}
	}

	body, err := os.ReadFile(store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: creation rule: %v\n", label, err)
		// Named because it is a dead end otherwise: this command edits that file
		// and cannot create one, having no way to know who else should read the
		// store.
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "faramir %s: `sudo faramir init` writes one naming "+
				"the keeper's own key, and this adds to it\n", label)
		}
		return 1
	}

	edited, changed, err := vault.EditRule(body, store.rulePath, recipient, adding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// No early return where the rule already says this: a pass that wrote the rule
	// and then failed on a file leaves exactly that state, so the reseal runs
	// either way and re-running is how such a pass is resumed.
	if !changed {
		fmt.Fprintf(os.Stderr, "faramir %s: %s already %s %s; checking the store agrees\n",
			label, store.rulePath, listedOrNot(adding), recipient)
	}

	wanted, err := vault.RuleRecipientsFrom(edited, store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Judged against the edit rather than the file on disk, and before the write:
	// a store sealed to a rule the keeper is not named in opens for nobody the
	// broker can ask, and re-running does not undo it.
	if err := vault.KeeperStaysAReader(store.keyPath, wanted, store.rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}

	if f.dryRun {
		if changed {
			fmt.Fprintf(os.Stderr, "faramir %s: would %s %s: %s would name %s\n",
				label, addOrRemove(adding), recipient, store.rulePath, strings.Join(wanted, ","))
		}
		return resealStore(label, store, wanted, true)
	}

	if !changed {
		return resealStore(label, store, wanted, false)
	}
	if err := vault.WriteBack(store.rulePath, edited); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, store.rulePath, err)
		return 1
	}
	// One record for the rule, before the per-file records the reseal writes, so
	// the log reads in the order it happened. Public keys only.
	audit.NewLog(store.cfg.Audit).Write(map[string]any{
		"op": opReader, "log_id": audit.NewLogID(), "file": store.rulePath,
		"change": addedOrRemoved(adding), "recipient": recipient, "to": wanted,
		"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
	}, audit.Output{})
	fmt.Fprintf(os.Stderr, "faramir %s: %s %s; %s now names %d recipient(s)\n",
		label, addedOrRemoved(adding), recipient, store.rulePath, len(wanted))

	// A rule the files are not yet sealed to is the state this command exists to
	// avoid, so its exit status is the reseal's.
	return resealStore(label, store, wanted, false)
}

// addOrRemove is the bare verb, for a sentence that already carries a "would".
func addOrRemove(adding bool) string {
	if adding {
		return "add"
	}
	return "remove"
}

func addedOrRemoved(adding bool) string {
	if adding {
		return "added"
	}
	return "removed"
}

func listedOrNot(adding bool) string {
	if adding {
		return "names"
	}
	return "does not name"
}

// runReaderList needs no root: .sops.yaml is world-readable, holding public
// keys and a rule and no value. It reads that file rather than asking the
// broker.
func runReaderList(f readerFlags) int {
	paint, bad := termui.PaletteFor("reader ls", f.when)
	if bad != 0 {
		return bad
	}
	cfg, err := loadResolved(socketDefault())
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir reader ls: %v\n", err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	recipients, err := vault.RuleRecipients(rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir reader ls: %v\n", err)
		return 1
	}
	// Sorted rather than left in the order the rule lists them: two hosts sealed
	// to the same set should print the same thing.
	slices.Sort(recipients)
	if f.json {
		out, err := json.Marshal(recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir reader ls: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}
	// Which of these is this host's own means reading the age key, which is the
	// keeper's and root's. So the note appears where it can be known and the
	// listing is plain where it cannot, rather than a column that says "no" and
	// means "could not tell".
	keeper, err := keygen.AgeRecipient(vault.AgeKeyPath(cfg))
	if err != nil {
		keeper = ""
	}
	for _, recipient := range recipients {
		if recipient != "" && recipient == keeper {
			// The note is faramir's word about the key, not part of it.
			fmt.Printf("%s  %s\n", termui.Safe(recipient), paint.Dim("(this host's keeper)"))
			continue
		}
		fmt.Println(termui.Safe(recipient))
	}
	return 0
}
