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
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
)

func cmdRekey(args []string) int {
	fs := newFlagSet("rekey", "rekey [options] [FILE...]")
	configPath := fs.String("config", "", "config file (default $FARAMIR_CONFIG, then the installed one)")
	ageKey := fs.String("age-key", "", "age key file (default: age.key beside the config)")
	sopsConfig := fs.String("sops-config", "", "creation rule to read the recipients from "+
		"(default: .sops.yaml beside the config)")
	dryRun := fs.Bool("dry-run", false, "report which files would be re-encrypted and write nothing")
	if code, ok := parseFlags(fs, args); !ok {
		return code
	}

	// Refused rather than attempted, like edit: as the operator this fails on the
	// age key with a bare permission error, and the fix is not obvious from it.
	if os.Geteuid() != 0 {
		fmt.Fprintln(os.Stderr, "faramir rekey must run as root, because the age key is "+
			"readable only by the keeper and by root: try 'sudo faramir rekey'")
		return 1
	}

	cfg, err := config.Load(resolveConfig(*configPath))
	if err != nil {
		fmt.Fprintf(os.Stderr, "config: %v\n", err)
		return 1
	}

	// Both kinds together: this is a diagnostic printed when the named file is
	// not among the managed ones, and the operator wants every reason.
	managed, failures, absent := keeper.Resolve(cfg.Secrets.Files)
	unresolvable := slices.Concat(failures, absent)
	targets, err := rekeyTargets(managed, fs.Args())
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		for _, reason := range unresolvable {
			fmt.Fprintf(os.Stderr, "  %s\n", reason)
		}
		return 1
	}
	// Reported even when enough resolved to proceed, unlike edit, which opens the
	// one file it was asked for.  Here a pattern that named nothing is a managed
	// file this run did not reach, and none may be left behind.
	for _, reason := range unresolvable {
		fmt.Fprintf(os.Stderr, "not reached: %s\n", reason)
	}

	rulePath := *sopsConfig
	if rulePath == "" {
		rulePath = filepath.Join(filepath.Dir(cfg.Path), ".sops.yaml")
	}
	wanted, err := ruleRecipients(rulePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	keyPath := *ageKey
	if keyPath == "" {
		keyPath = filepath.Join(filepath.Dir(cfg.Path), "age.key")
	}
	if _, err := os.Stat(keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "age key: %v\n", err)
		return 1
	}
	// Checked before anything is decrypted.  Re-encrypting to a rule the keeper is
	// not named in produces a secrets directory that opens for nobody the broker
	// can ask, one file at a time, and the failure only shows up at the next
	// refresh.
	if err := keeperStaysAReader(keyPath, wanted, rulePath); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		return 1
	}

	log := audit.NewLog(cfg.Audit)
	failed, changed := 0, 0
	for _, target := range targets {
		was, err := recipientsOf(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", target, err)
			failed++
			continue
		}
		if sameRecipients(was, wanted) {
			fmt.Fprintf(os.Stderr, "unchanged %s\n", target)
			continue
		}
		if *dryRun {
			fmt.Fprintf(os.Stderr, "would re-encrypt %s: %s -> %s\n",
				target, strings.Join(was, ","), strings.Join(wanted, ","))
			changed++
			continue
		}

		err = reencrypt(target, keyPath, wanted)
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
			fmt.Fprintf(os.Stderr, "%s: %v\n", target, err)
			failed++
			continue
		}
		fmt.Fprintf(os.Stderr, "re-encrypted %s: %s -> %s\n",
			target, strings.Join(was, ","), strings.Join(wanted, ","))
		changed++
	}

	// Named rather than left implicit: a rekey that reached only some of the files
	// is the state an operator has to know about, because the rest is still sealed
	// to the old recipients.
	if failed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d file(s) could not be re-encrypted; "+
			"those still open to the recipients they had\n", failed, len(targets))
		return 1
	}
	if *dryRun {
		fmt.Fprintf(os.Stderr, "%d of %d file(s) would change\n", changed, len(targets))
		return 0
	}
	if changed > 0 {
		fmt.Fprintf(os.Stderr, "%d of %d file(s) re-encrypted; the broker picks them "+
			"up within one refresh interval\n", changed, len(targets))
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

// ruleAgeRecipient matches the age keys listed under a creation rule.  Read
// with a regex for the reason recipientsOf is: the sops libraries are kept out
// of this binary deliberately, and a YAML parser for one cleartext list would
// undo that.
var ruleAgeRecipient = regexp.MustCompile(`(age1[0-9a-z]+)`)

// ruleCreationRule counts the rules in the file, because the regex above reads
// the whole of it.
var ruleCreationRule = regexp.MustCompile(`(?m)^\s*-\s+path_regex\s*:`)

// ruleRecipients reads who .sops.yaml says a managed file should be encrypted
// to.
//
// One creation rule only.  The shipped file has exactly one, matching any
// *.sops.yml wherever it sits, so every managed file is governed by the same
// list and reading the whole file is reading that list.  With two rules the
// answer depends on which one a path matches, which is a path_regex question
// this cannot answer, so it refuses rather than re-encrypting half the secrets
// directory to the wrong set.
func ruleRecipients(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	if rules := len(ruleCreationRule.FindAll(body, -1)); rules > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and which one governs a "+
			"file depends on its path_regex: re-key those with 'sops updatekeys' "+
			"per file, or name a single-rule file with --sops-config", path, rules)
	}
	var out []string
	for _, match := range ruleAgeRecipient.FindAllSubmatch(body, -1) {
		if recipient := string(match[1]); !slices.Contains(out, recipient) {
			out = append(out, recipient)
		}
	}
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
// the creation rule selects by path_regex, so the temporary copy has to keep
// the target's own name to match the rule at all.
func reencrypt(target, keyPath string, recipients []string) error {
	decrypted, err := runSops(keyPath, "--decrypt", target)
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
	// The recipients are named on the command line rather than found by sops,
	// which resolves .sops.yaml by walking up from the file being encrypted and
	// would walk out of /dev/shm and match no rule at all.
	sealed, err := runSops(keyPath, "--encrypt", "--age", strings.Join(recipients, ","), plain)
	if err != nil {
		return fmt.Errorf("encrypt: %w", err)
	}
	return writeBack(target, sealed)
}
