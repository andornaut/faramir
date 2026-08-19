package main

// `faramir recipient` manages who can decrypt the managed store: the rule and
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
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// opRecipient is the audit record a rule change writes, one per command: the
// per-file records are the reseal's own, and what this adds is who the store is
// now readable by and who asked for that.
const opRecipient = "recipient"

// newRecipientCmd is a group spelled like `link add|rm|ls`. The guard names a
// subcommand by every token a person types, so the three here are three lines
// in cli.Operator, held against the command tree by a test.
func newRecipientCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "recipient",
		Short:   "who can decrypt the managed store",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		RunE:    func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newRecipientAddCmd(), newRecipientRemoveCmd(), newRecipientListCmd(),
		newRecipientResealCmd())
	return c
}

type recipientFlags struct {
	configPath string
	dryRun     bool
	json       bool
}

func (f *recipientFlags) register(c *cobra.Command, writes bool) {
	fl := c.Flags()
	fl.StringVarP(&f.configPath, "config", "c", "",
		"config file (default $FARAMIR_CONFIG, then the installed one)")
	if !writes {
		fl.BoolVar(&f.json, "json", false, "print the recipients as JSON")
		return
	}
	fl.BoolVar(&f.dryRun, "dry-run", false,
		"report the rule change and which files would be re-encrypted, and write neither")
}

func newRecipientAddCmd() *cobra.Command {
	var f recipientFlags
	c := &cobra.Command{
		Use:   "add [options] RECIPIENT",
		Short: "let one more key decrypt the managed store",
		Long: "Adds an age recipient to .sops.yaml and re-encrypts every managed file to\n" +
			"it, so the rule and the ciphertext never disagree.\n\n" +
			"RECIPIENT is a PUBLIC key: an age1... recipient or an ssh public key. The\n" +
			"private half is refused, .sops.yaml being world-readable. Mint one with\n" +
			"'age-keygen -o FILE' on the machine that will hold it.",
		Args: exactlyArgs(1, "one age recipient"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runRecipientChange(f, args[0], true))
		},
	}
	f.register(c, true)
	return c
}

func newRecipientRemoveCmd() *cobra.Command {
	var f recipientFlags
	c := &cobra.Command{
		Use:     "rm [options] RECIPIENT",
		Aliases: []string{"remove"},
		Short:   "stop one key from decrypting the managed store",
		Long: "Removes an age recipient from .sops.yaml and re-encrypts every managed\n" +
			"file without it.\n\n" +
			"This reaches no copy of the ciphertext somebody already holds. Treat what\n" +
			"that key could read as read, and rotate it.",
		Args: exactlyArgs(1, "one age recipient"),
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runRecipientChange(f, args[0], false))
		},
	}
	f.register(c, true)
	return c
}

func newRecipientListCmd() *cobra.Command {
	var f recipientFlags
	c := &cobra.Command{
		Use:     "ls [options]",
		Aliases: []string{"list"},
		Short:   "who can decrypt the managed store",
		Args:    noArgs,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runRecipientList(f)) },
	}
	f.register(c, false)
	return c
}

func newRecipientResealCmd() *cobra.Command {
	var f recipientFlags
	c := &cobra.Command{
		Use:   "reseal [options] [FILE...]",
		Short: "re-encrypt the store to the recipients .sops.yaml names",
		Long: "Makes the ciphertext agree with the rule, for the cases `add` and `rm`\n" +
			"cannot reach: a `.sops.yaml` changed some other way, and a pass that\n" +
			"failed partway and has to be resumed against a rule that is already\n" +
			"right.\n\n" +
			"Every managed file unless some are named. Files already sealed to the\n" +
			"rule are skipped, so a run that has nothing to do writes nothing.",
		RunE: func(c *cobra.Command, args []string) error { return codeErr(runReseal(f, args)) },
	}
	f.register(c, true)
	return c
}

// runReseal is a recipient change with no recipient: the rule is taken as it
// stands and the store is brought to it.
func runReseal(f recipientFlags, args []string) int {
	const label = "recipient reseal"
	store, code := loadStore(label, f.configPath, socketDefault(), args, false)
	if store == nil {
		return code
	}
	wanted, err := ruleRecipients(store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Checked before anything is decrypted: re-encrypting to a rule the keeper is
	// not named in produces a secrets directory that opens for nobody the broker
	// can ask, one file at a time.
	if err := keeperStaysAReader(store.keyPath, wanted, store.rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	return resealStore(label, store, wanted, f.dryRun)
}

// runRecipientChange is add and rm, which differ only in the edit they ask for.
// The order is the point: validate, edit in memory, judge the result, and only
// then write, so a rule that would leave the keeper out is one the file never
// comes to hold.
func runRecipientChange(f recipientFlags, recipient string, adding bool) int {
	label := "recipient rm"
	if adding {
		label = "recipient add"
		// Before root and before the config: a typo in a public key should not need
		// sudo to find out about.
		if err := agekey.ValidateRecipient(recipient); err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
	}

	store, code := loadStore(label, f.configPath, socketDefault(), nil, true)
	if store == nil {
		return code
	}
	// Named here rather than left to keeperStaysAReader below, whose advice is to
	// put the key back under `- age:`: to an operator who has just asked to
	// remove it, that reads as an instruction to undo what they typed.
	if !adding {
		if keeper, err := agekey.Recipient(store.keyPath); err == nil && keeper == recipient {
			fmt.Fprintf(os.Stderr, "faramir %s: %s is the key %s decrypts with, so removing "+
				"it would leave a store nothing on this host can open and a broker serving "+
				"nothing. It is the one recipient this command will not take away\n",
				label, recipient, store.keyPath)
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

	edited, changed, err := editRule(body, store.rulePath, recipient, adding)
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

	wanted, err := ruleRecipientsFrom(edited, store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Judged against the edit rather than the file on disk, and before the write:
	// a store sealed to a rule the keeper is not named in opens for nobody the
	// broker can ask, and re-running does not undo it.
	if err := keeperStaysAReader(store.keyPath, wanted, store.rulePath); err != nil {
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
	if err := writeBack(store.rulePath, edited); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, store.rulePath, err)
		return 1
	}
	// One record for the rule, before the per-file records the reseal writes, so
	// the log reads in the order it happened. Public keys only.
	audit.NewLog(store.cfg.Audit).Write(map[string]any{
		"op": opRecipient, "log_id": audit.NewLogID(), "file": store.rulePath,
		"change": addedOrRemoved(adding), "recipient": recipient, "to": wanted,
		"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
	}, audit.Output{})
	fmt.Fprintf(os.Stderr, "faramir %s: %s %s; %s now names %d recipient(s)\n",
		label, addedOrRemoved(adding), recipient, store.rulePath, len(wanted))

	// A rule the files are not yet sealed to is the state this command exists to
	// avoid, so its exit status is the reseal's.
	return resealStore(label, store, wanted, false)
}

// editRule is the one call that differs between add and rm.
func editRule(body []byte, path, recipient string, adding bool) ([]byte, bool, error) {
	if adding {
		return sopsrule.Add(body, path, recipient)
	}
	return sopsrule.Remove(body, path, recipient)
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

// runRecipientList needs no root: .sops.yaml is world-readable, holding public
// keys and a rule and no value. It reads that file rather than asking the
// broker.
func runRecipientList(f recipientFlags) int {
	cfg, err := config.Load(resolveConfig(f.configPath, socketDefault()))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir recipient ls: %v\n", err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	recipients, err := ruleRecipients(rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir recipient ls: %v\n", err)
		return 1
	}
	if f.json {
		out, err := json.Marshal(recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir recipient ls: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}
	// Which of these is this host's own means reading the age key, which is the
	// keeper's and root's. So the note appears where it can be known and the
	// listing is plain where it cannot, rather than a column that says "no" and
	// means "could not tell".
	keeper, err := agekey.Recipient(ageKeyPath(cfg))
	if err != nil {
		keeper = ""
	}
	for _, recipient := range recipients {
		if recipient != "" && recipient == keeper {
			fmt.Printf("%s  (this host's keeper)\n", recipient)
			continue
		}
		fmt.Println(recipient)
	}
	return 0
}
