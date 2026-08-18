package main

// `faramir sops recipient` manages who can decrypt the managed store: the rule
// and the ciphertext together, in one command.
//
// The two were separate, an editor for `.sops.yaml` and `rekey` for the files,
// and between them lay a state nothing reports: a rule naming a reader the
// existing files are not sealed to.  Nothing fails there.  New files get the new
// list, old ones keep the old, and the divergence surfaces whenever somebody
// next reaches for a value with a key they were told they had.
//
// So the rule is written and the store is re-encrypted by the same command, and
// the rule is judged before it is written rather than after.  `rekey` stays for
// what this cannot cover: a run that reached only some of the files, and a file
// edited by hand, root being able to write a root-owned file whatever the docs
// say.

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

// opRecipient is the audit record a rule change writes, one per command rather
// than one per file: the per-file records are the rekey's own, and what this
// adds is who the store is now readable by and who asked for that.
const opRecipient = "recipient"

// Flat under `sops` rather than a group of its own.  The guard maps a subcommand
// to a name one level deep, which is as deep as this CLI nests, and that mapping
// is what decides whose arguments go unscanned: deepening it for three commands
// would put a security-relevant list a level further from what a person types.
type recipientFlags struct {
	configPath string
	ageKey     string
	dryRun     bool
	socket     string
	json       bool
}

func (f *recipientFlags) register(c *cobra.Command, writes bool) {
	fl := c.Flags()
	fl.StringVarP(&f.configPath, "config", "c", "",
		"config file (default $FARAMIR_CONFIG, then the installed one)")
	fl.StringVar(&f.socket, "socket", socketDefault(),
		"broker socket to ask where the install is ($FARAMIR_SOCKET)")
	if !writes {
		fl.BoolVar(&f.json, "json", false, "print the recipients as JSON")
		return
	}
	fl.StringVar(&f.ageKey, "age-key", "", "age key file (default: age.key beside the config)")
	fl.BoolVar(&f.dryRun, "dry-run", false,
		"report the rule change and which files would be re-encrypted, and write neither")
}

func newRecipientAddCmd() *cobra.Command {
	var f recipientFlags
	c := &cobra.Command{
		Use:   "add-recipient [options] RECIPIENT",
		Short: "let one more key decrypt the managed store",
		Long: "Adds an age recipient to .sops.yaml and re-encrypts every managed file to\n" +
			"it, so the rule and the ciphertext never disagree.\n\n" +
			"RECIPIENT is a PUBLIC key: an age1... recipient or an ssh public key. The\n" +
			"private half is refused, .sops.yaml being world-readable. Mint one with\n" +
			"'faramir sops keygen -o FILE' on the machine that will hold it.",
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
		Use:     "rm-recipient [options] RECIPIENT",
		Aliases: []string{"remove-recipient"},
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
		Use:   "recipients [options]",
		Short: "who can decrypt the managed store",
		Args:  noArgs,
		RunE:  func(c *cobra.Command, args []string) error { return codeErr(runRecipientList(f)) },
	}
	f.register(c, false)
	return c
}

// runRecipientChange is add and rm, which differ only in the edit they ask for.
//
// The order is the whole point: validate, edit in memory, judge the result, and
// only then write.  A rule that would leave the keeper out, or that this cannot
// read back, is one the file never comes to hold, so there is no state to
// recover from.
func runRecipientChange(f recipientFlags, recipient string, adding bool) int {
	label := "sops rm-recipient"
	if adding {
		label = "sops add-recipient"
		// Before root, before the config, before anything: a typo in a public key
		// should not need sudo to find out about.
		if err := agekey.ValidateRecipient(recipient); err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
			return 1
		}
	}

	store, code := loadStore(label, f.configPath, f.socket, f.ageKey, nil)
	if store == nil {
		return code
	}
	body, err := os.ReadFile(store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: creation rule: %v\n", label, err)
		return 1
	}

	edited, changed, err := editRule(body, store.rulePath, recipient, adding)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	if !changed {
		fmt.Fprintf(os.Stderr, "faramir %s: %s already %s %s; nothing to do\n",
			label, store.rulePath, listedOrNot(adding), recipient)
		return 0
	}

	wanted, err := ruleRecipientsFrom(edited, store.rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}
	// Judged against the edit rather than the file on disk, and before the write.
	// A store sealed to a rule the keeper is not named in opens for nobody the
	// broker can ask, and re-running does not undo it.
	if err := keeperStaysAReader(store.keyPath, wanted, store.rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return 1
	}

	if f.dryRun {
		fmt.Fprintf(os.Stderr, "faramir %s: would %s %s: %s now names %s\n",
			label, addedOrRemoved(adding), recipient, store.rulePath, strings.Join(wanted, ","))
		return rekeyStore(label, store, wanted, true)
	}

	if err := writeBack(store.rulePath, edited); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, store.rulePath, err)
		return 1
	}
	// One record for the rule, before the per-file records the rekey writes, so
	// the log reads in the order it happened.  Public keys only; no value of any
	// kind passes through here.
	audit.NewLog(store.cfg.Audit).Write(map[string]any{
		"op": opRecipient, "log_id": audit.NewLogID(), "file": store.rulePath,
		"change": addedOrRemoved(adding), "recipient": recipient, "to": wanted,
		"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
	}, audit.Output{})
	fmt.Fprintf(os.Stderr, "faramir %s: %s %s; %s now names %d recipient(s)\n",
		label, addedOrRemoved(adding), recipient, store.rulePath, len(wanted))

	// A rule the files are not yet sealed to is the state this command exists to
	// avoid, so its exit status is the rekey's: a partial pass is a failure here
	// even though the rule was written.
	return rekeyStore(label, store, wanted, false)
}

// editRule is the one call that differs between add and rm.
func editRule(body []byte, path, recipient string, adding bool) ([]byte, bool, error) {
	if adding {
		return sopsrule.Add(body, path, recipient)
	}
	return sopsrule.Remove(body, path, recipient)
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
// keys and a rule and no value.  It reads that file rather than asking the
// broker, the question being who the store is sealed to rather than what is in
// it.
func runRecipientList(f recipientFlags) int {
	cfg, err := config.Load(resolveConfig(f.configPath, f.socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir sops recipients: %v\n", err)
		return 1
	}
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	recipients, err := ruleRecipients(rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir sops recipients: %v\n", err)
		return 1
	}
	if f.json {
		out, err := json.Marshal(recipients)
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir sops recipients: %v\n", err)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}
	for _, recipient := range recipients {
		fmt.Println(recipient)
	}
	return 0
}
