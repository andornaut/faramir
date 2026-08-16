package main

// `faramir rekey` applies a changed `.sops.yaml` to a secrets directory that
// was encrypted before it changed.  What that is for is docs/operating.md.
//
// It walks the managed files rather than leaving the operator to run `sops
// updatekeys` per file, which rewrites in place with no regard for ownership: a
// managed file that stops being readable by the secrets group is one the keeper
// cannot open.  Ownership is preserved by the same writeBack an edit uses, and
// each file is recorded in the audit log the way an edit is.
//
// It runs as root for the same reason edit does: the age key is readable by the
// keeper and by root, and re-encrypting means decrypting first.

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
)

type rekeyFlags struct {
	configPath string
	ageKey     string
	dryRun     bool
	socket     string
}

func newRekeyCmd() *cobra.Command {
	var f rekeyFlags
	c := &cobra.Command{
		Use:     "rekey [options] [FILE...]",
		Short:   "re-encrypt the secrets directory to the recipients .sops.yaml now names",
		GroupID: groupProvisioning,
		RunE:    func(c *cobra.Command, args []string) error { return codeErr(runRekey(f, args)) },
	}
	c.Flags().StringVarP(&f.configPath, "config", "c", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	c.Flags().StringVar(&f.ageKey, "age-key", "", "age key file (default: age.key beside the config)")
	c.Flags().BoolVar(&f.dryRun, "dry-run", false, "report which files would be re-encrypted and write nothing")
	c.Flags().StringVar(&f.socket, "socket", socketDefault(), "broker socket to ask where the install is ($FARAMIR_SOCKET)")
	return c
}

func runRekey(f rekeyFlags, args []string) int {

	// Refused rather than attempted, like edit: as the operator this fails on the
	// age key with a bare permission error, and the fix is not obvious from it.
	if !requireRoot("rekey", "the age key is readable only by the keeper and by root") {
		return 1
	}

	cfg, err := config.Load(resolveConfig(f.configPath, f.socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir rekey: %v\n", err)
		return 1
	}

	// Both kinds together: this is a diagnostic printed when the named file is
	// not among the managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secrets.Patterns)
	unresolvable := slices.Concat(failures, absent)
	targets, err := rekeyTargets(managed, args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir rekey: %v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}
	// Reported even when enough resolved to proceed, unlike edit, which opens the
	// one file it was asked for.  Here a pattern that named nothing is a managed
	// file this run did not reach, and none may be left behind.
	for _, reason := range unresolvable {
		fmt.Fprintf(os.Stderr, "faramir rekey: not reached: %s\n", reason)
	}

	// This install's own rules, and no flag naming another.  What this command is
	// for is making the ciphertext agree with what <config-dir>/.sops.yaml says,
	// so a run sealing the secrets directory to some other file's recipients
	// produces the state it exists to remove: a host whose ciphertext and whose
	// rule name different readers, with `doctor` and every file sops creates from
	// then on still reading the rule.  --config moves the whole install, which is
	// the honest way to act on another one.
	rulePath := filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	wanted, err := ruleRecipients(rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir rekey: %v\n", err)
		return 1
	}

	keyPath := f.ageKey
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.Path), "age.key")
	}
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir rekey: age key: %v\n", err)
		return 1
	}
	// Checked before anything is decrypted.  Re-encrypting to a rule the keeper is
	// not named in produces a secrets directory that opens for nobody the broker
	// can ask, one file at a time, and the failure only shows up at the next
	// refresh.
	if err := keeperStaysAReader(keyPath, wanted, rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir rekey: %v\n", err)
		return 1
	}

	log := audit.NewLog(cfg.Audit)
	failed, changed := 0, 0
	for _, target := range targets {
		was, err := recipientsOf(target)
		if err != nil {
			// Recorded like every other outcome of this loop.  A file this run could
			// not read is one it did not reach, and a log that says nothing about it
			// reads as a rekey that covered the whole secrets directory.
			//
			// Not on a dry run, which writes nothing at all: the log is a record of
			// what a run did to this host, and a run that was asked to do nothing did
			// nothing to it.
			if !f.dryRun {
				log.Write(map[string]any{
					"op": "rekey", "log_id": audit.NewLogID(), "file": target,
					"error": err.Error(),
					"uid":   os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
				}, audit.Output{})
			}
			fmt.Fprintf(os.Stderr, "faramir rekey: %s: %v\n", target, err)
			failed++
			continue
		}
		if sameRecipients(was, wanted) {
			fmt.Fprintf(os.Stderr, "faramir rekey: unchanged %s\n", target)
			continue
		}
		if f.dryRun {
			fmt.Fprintf(os.Stderr, "faramir rekey: would re-encrypt %s: %s -> %s\n",
				target, strings.Join(was, ","), strings.Join(wanted, ","))
			changed++
			continue
		}

		err = reencrypt(keyPath, rulePath, wanted, target)
		// One record per file, naming the recipients on both sides and never the
		// values: who can read the secrets directory is exactly what an operator
		// needs the log to be able to answer afterwards.
		record := map[string]any{
			"op": "rekey", "log_id": audit.NewLogID(), "file": target,
			"from": was, "to": wanted,
			"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
		}
		if err != nil {
			record["error"] = err.Error()
		}
		log.Write(record, audit.Output{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir rekey: %s: %v\n", target, err)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "faramir rekey: re-encrypted %s: %s -> %s\n",
			target, strings.Join(was, ","), strings.Join(wanted, ","))
		changed++
	}

	// Named rather than left implicit: a rekey that reached only some of the files
	// is the state an operator has to know about, because the rest is still sealed
	// to the old recipients.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "faramir rekey: %d of %d file(s) could not be re-encrypted; "+
			"those still open to the recipients they had\n", failed, len(targets))
		return 1
	}
	if f.dryRun {
		fmt.Fprintf(os.Stderr, "faramir rekey: %d of %d file(s) would change\n", changed, len(targets))
		return 0
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "faramir rekey: %d of %d file(s) re-encrypted; the broker "+
			"picks them up within one refresh interval\n", changed, len(targets))
	}
	return 0
}

// rekeyTargets is every managed file, or just the ones named.
//
// Naming none is the command's usual shape, so it is the default; naming
// some is for a secrets directory where one file is meant to stay as it is.
// Either way a path that is not managed is refused by resolveManaged, so a
// rekey cannot walk out of the secrets directory.
func rekeyTargets(managed, named []string) ([]string, error) {
	if len(named) == 0 {
		if len(managed) == 0 {
			return nil, errNoManagedFiles
		}
		return managed, nil
	}
	out := make([]string, 0, len(named))
	for _, arg := range named {
		target, err := resolveManaged(managed, arg)
		if err != nil {
			return nil, err
		}
		if !slices.Contains(out, target) {
			out = append(out, target)
		}
	}
	return out, nil
}

// ruleRecipients reads who .sops.yaml says a managed file should be encrypted
// to.
//
// One creation rule only.  The shipped file has exactly one, matching any
// *.sops.yml wherever it sits, so every managed file is governed by the same
// list.  With two rules the answer depends on which one a path matches, which is
// a path_regex question this cannot answer, so it refuses rather than
// re-encrypting half the secrets directory to the wrong set.
func ruleRecipients(path string) ([]string, error) {
	rules, err := sopsrule.Load(path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	if len(rules) > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and which one governs a "+
			"file depends on its path_regex: re-key those with 'sops updatekeys' "+
			"per file, which is the only thing that can answer it", path, len(rules))
	}
	for _, rule := range rules {
		// A split data key is refused rather than flattened.  shamir_threshold means
		// N of the key groups have to come together to open the file, and this
		// re-encrypts to one list of recipients, which is one group holding every
		// key: any one of them would then open what took N of them before.  That is
		// the same mistake as widening the recipient list, made to a rule that was
		// written to narrow it.
		if rule.ShamirThreshold > 0 {
			return nil, fmt.Errorf("%s sets shamir_threshold, so the data key is "+
				"split across key groups and %d of them are needed together: "+
				"re-encrypting here would seal it to one group holding every key, and "+
				"any one of them would open it. Re-key with 'sops updatekeys' per file",
				path, rule.ShamirThreshold)
		}
	}
	out := sopsrule.Recipients(rules)
	if len(out) == 0 {
		return nil, fmt.Errorf("%s names no age recipient, so there is nothing to "+
			"re-encrypt to; faramir manages age-encrypted files only", path)
	}
	return out, nil
}

// keeperStaysAReader refuses a rule that leaves out the key this host decrypts
// with.
//
// The recipients are public keys, so the check is the public half of the age
// key against the list.  Getting this wrong is not recoverable by re-running:
// the files would already be sealed to a set that no longer includes the only
// identity on the host.
func keeperStaysAReader(keyPath string, wanted []string, rulePath string) error {
	recipient, err := agekey.Recipient(keyPath)
	if err != nil {
		return fmt.Errorf("age key: %w", err)
	}
	if slices.Contains(wanted, recipient) {
		return nil
	}
	return fmt.Errorf("%s does not list %s, which is the key %s decrypts with: "+
		"re-encrypting to it would leave a secrets directory the keeper cannot open, and the "+
		"broker would come up serving nothing. Add it under '- age:' first",
		rulePath, recipient, keyPath)
}

// sameRecipients compares the two sets regardless of the order they are written
// in, so a rule that merely lists the same keys differently rewrites nothing.
func sameRecipients(was, wanted []string) bool {
	if len(was) != len(wanted) {
		return false
	}
	a, b := slices.Clone(was), slices.Clone(wanted)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}

// reencrypt rewrites one managed file, sealed to the given recipients.
//
// The plaintext goes through a 0600 file in a tmpfs rather than through this
// process's memory and back, because sops encrypts a file and takes its name:
// the file's own name is what decides its format, so the copy keeps it.  Which
// creation rule governs it is settled by --filename-override rather than by
// where the copy sits; see sealTo.
func reencrypt(keyPath, rulePath string, recipients []string, target string) error {
	decrypted, err := runSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	dir, err := os.MkdirTemp("/dev/shm", "faramir-rekey-")
	if err != nil {
		return fmt.Errorf("temporary directory: %w", err)
	}
	// Registered first so it runs last; see editManaged.
	defer removeOnSignal(dir)()
	defer func() { _ = os.RemoveAll(dir) }()

	plain := filepath.Join(dir, filepath.Base(target))
	if err := os.WriteFile(plain, decrypted, 0o600); err != nil {
		return err
	}
	sealed, err := sealTo(keyPath, rulePath, target, recipients, plain)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return writeBack(target, sealed)
}
