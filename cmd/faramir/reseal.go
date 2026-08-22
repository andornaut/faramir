package main

// Re-encrypting the managed store to what `.sops.yaml` says, which is the
// second half of every recipient change and the whole of `recipient reseal`.
// What that is for is docs/operating.md.
//
// It walks the managed files rather than leaving the operator to run `sops
// updatekeys` per file, which rewrites in place with no regard for ownership: a
// managed file that stops being readable by the secrets group is one the keeper
// cannot open. Ownership is preserved by the same writeBack an edit uses, and
// each file is recorded in the audit log.
//
// It runs as root for the same reason edit does: the age key is readable by the
// keeper and by root, and re-encrypting means decrypting first.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// storeContext is what any command that re-encrypts the managed store needs:
// where this install keeps its config, its rule and its key, and which files the
// run is to reach.
type storeContext struct {
	cfg      *config.Config
	keyPath  string
	rulePath string
	targets  []string
}

// loadStore is the preamble every such command shares. It returns nil and an
// exit code where the run cannot proceed, having already said why.
//
// label is how the command names itself in its messages, so an operator reading
// a failure sees the command they ran. emptyStoreOK says whether a store
// naming no file yet is a reason to stop: it is for `reseal`, whose whole job
// is files, and not for a recipient change, the rule governing what sops writes
// from now on.
func loadStore(label, socket string, named []string,
	emptyStoreOK bool) (*storeContext, int) {
	// Blocked rather than attempted, like edit: as the operator this fails on the
	// age key with a bare permission error.
	if !requireRoot(label, "the age key is readable only by the keeper and by root") {
		return nil, 1
	}
	cfg, err := config.Load(resolveConfig(socket))
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		return nil, 1
	}

	keyPath := ageKeyPath(cfg)
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: age key: %v\n", label, err)
		return nil, 1
	}

	// Both kinds together: this is printed when the named file is not among the
	// managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secret.Patterns)
	unresolvable := slices.Concat(failures, absent)
	targets, err := resealTargets(managed, named)
	if err != nil && emptyStoreOK && errors.Is(err, errNoFilesToReseal) {
		// Said once, and the per-pattern reasons dropped with it: each is "this glob
		// matched nothing", which reads as three problems on a host whose first
		// secret has not been written.
		fmt.Fprintf(os.Stderr, "faramir %s: the managed store names no file yet, so "+
			"there is nothing to re-encrypt; the rule governs what sops writes from "+
			"now on\n", label)
		return &storeContext{
			cfg:      cfg,
			keyPath:  keyPath,
			rulePath: filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml"),
		}, 0
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir %s: %v\n", label, err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return nil, 1
	}
	// Reported even when enough resolved to proceed, unlike edit, which opens the
	// one file it was asked for: here a pattern that named nothing is a managed
	// file this run did not reach.
	for _, reason := range unresolvable {
		fmt.Fprintf(os.Stderr, "faramir %s: not reached: %s\n", label, reason)
	}

	// This install's own rule, and no flag naming another: these commands make
	// the ciphertext agree with <config-dir>/.sops.yaml, so a run sealing the
	// secrets directory to another file's recipients produces the state they
	// exist to remove. --config moves the whole install.
	return &storeContext{
		cfg:      cfg,
		keyPath:  keyPath,
		rulePath: filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml"),
		targets:  targets,
	}, 0
}

// errNoFilesToReseal is errNoManagedFiles said for this command: nothing to
// re-encrypt rather than nothing to open.
var errNoFilesToReseal = errors.New("no managed sops files: the managed store " +
	"named none, so there is nothing to re-encrypt. Write the first one with " +
	"`faramir vault add NAME`")

// ageKeyPath is the key a run decrypts with: the install's own, beside its
// config, and no flag names another. A flag would name which key
// keeperStaysAReader checks, so a run pointed at a second identity could take
// the host's own key out of the rule and reseal the store without it, which no
// re-run undoes.
func ageKeyPath(cfg *config.Config) string {
	return filepath.Join(filepath.Dir(cfg.Path), "age.key")
}

// resealStore re-encrypts every target to wanted.
func resealStore(label string, store *storeContext, wanted []string, dryRun bool) int {
	targets := store.targets
	if len(targets) == 0 {
		return 0
	}
	log := audit.NewLog(store.cfg.Audit)
	failed, changed := 0, 0
	for _, target := range targets {
		was, err := sopsrule.SealedTo(target)
		if err != nil {
			// Recorded like every other outcome of this loop: a file this run could
			// not read is one it did not reach, and a log silent about it reads as a
			// reseal that covered the whole secrets directory. Not on a dry run,
			// which does nothing to this host.
			if !dryRun {
				log.Write(map[string]any{
					"op": opReseal, "log_id": audit.NewLogID(), "file": target,
					"error": err.Error(),
					"uid":   os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
				}, audit.Output{})
			}
			fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, target, err)
			failed++
			continue
		}
		if sopsrule.Same(was, wanted) {
			fmt.Fprintf(os.Stderr, "faramir %s: unchanged %s\n", label, target)
			continue
		}
		if dryRun {
			fmt.Fprintf(os.Stderr, "faramir %s: would re-encrypt %s: %s -> %s\n",
				label, target, strings.Join(was, ","), strings.Join(wanted, ","))
			changed++
			continue
		}

		err = reencrypt(store.keyPath, store.rulePath, wanted, target)
		// One record per file, naming the recipients on both sides and never the
		// values: who can read the secrets directory is what an operator needs the
		// log to answer afterwards.
		record := map[string]any{
			"op": opReseal, "log_id": audit.NewLogID(), "file": target,
			"from": was, "to": wanted,
			"uid": os.Getuid(), "sudo": os.Getenv("SUDO_USER"),
		}
		if err != nil {
			record["error"] = err.Error()
		}
		log.Write(record, audit.Output{})
		if err != nil {
			fmt.Fprintf(os.Stderr, "faramir %s: %s: %v\n", label, target, err)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "faramir %s: re-encrypted %s: %s -> %s\n",
			label, target, strings.Join(was, ","), strings.Join(wanted, ","))
		changed++
	}

	// Named rather than left implicit: a reseal that reached only some of the
	// files leaves the rest sealed to the old recipients.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) could not be re-encrypted; "+
			"those still open to the recipients they had\n", label, failed, len(targets))
		return 1
	}
	if dryRun {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) would change\n", label, changed, len(targets))
		return 0
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "faramir %s: %d of %d file(s) re-encrypted; the broker "+
			"picks them up within one refresh interval\n", label, changed, len(targets))
	}
	return 0
}

// resealTargets is every managed file, or just the ones named, which is for a
// secrets directory where one file is meant to stay as it is. Either way a
// path that is not managed is refused by resolveManaged, so a reseal cannot
// walk out of the secrets directory.
func resealTargets(managed, named []string) ([]string, error) {
	if len(named) == 0 {
		if len(managed) == 0 {
			return nil, errNoFilesToReseal
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
// to. One creation rule only: the shipped file has exactly one, matching any
// *.sops.yml wherever it sits. With two the answer depends on which path_regex
// a file matches, which this cannot answer, so it refuses rather than
// re-encrypting half the secrets directory to the wrong set.
func ruleRecipients(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	return ruleRecipientsFrom(body, path)
}

// ruleRecipientsFrom is ruleRecipients for a caller holding the bytes, which is
// what a command that has edited the rule and not yet written it has: a rule
// this refuses is one the file should never come to hold.
func ruleRecipientsFrom(body []byte, path string) ([]string, error) {
	rules, err := sopsrule.Parse(body, path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	if len(rules) > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and which one governs a "+
			"file depends on its path_regex: re-key those with 'sops updatekeys' "+
			"per file, which is the only thing that can answer it", path, len(rules))
	}
	for _, rule := range rules {
		// A split data key is refused rather than flattened: shamir_threshold means
		// N key groups have to come together to open the file, and this re-encrypts
		// to one list of recipients, so any one of them would open what took N
		// before.
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
// with. The recipients are public keys, so the check is the public half of the
// age key against the list. Getting it wrong is not recoverable by re-running:
// the files would already be sealed to a set without the only identity on the
// host.
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

// reencrypt rewrites one managed file, sealed to the given recipients. The
// plaintext goes through a 0600 file in a tmpfs because sops encrypts a file
// and takes its name, which is what decides its format, so the copy keeps it.
// Which creation rule governs it is settled by --filename-override; see
// sealTo.
func reencrypt(keyPath, rulePath string, recipients []string, target string) error {
	decrypted, err := runSops(keyPath, rulePath, "--decrypt", target)
	if err != nil {
		return fmt.Errorf("decrypt: %w", err)
	}
	dir, err := os.MkdirTemp("/dev/shm", "faramir-reseal-")
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
