package vault

import (
	"fmt"
	"os"
	"os/exec"
	"slices"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/keygen"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// sopsConfigPath is the creation rules to hand sops, and /dev/null where there
// are none. A rule file that is not there is not the same as none: sops
// refuses to start on a --config it cannot read, decrypt included, where
// /dev/null parses as a document with no creation rules.
func sopsConfigPath(rulePath string) string {
	if rulePath != "" && hostfs.Exists(rulePath) {
		return rulePath
	}
	return os.DevNull
}

// ruleMustCover refuses an edit the creation rules cannot write back, or nil.
// A host with no rule encrypts with sops' defaults, which cover every file, and
// sopsConfigPath has already turned that into /dev/null.
//
// A probe that cannot be put is not a refusal: what is ruled out is the case
// certain to fail later.
func ruleMustCover(rulePath, target string, recipients []string) error {
	configPath := sopsConfigPath(rulePath)
	if configPath == os.DevNull {
		return nil
	}
	if err := ruleMustNotSplitTheKey(rulePath); err != nil {
		return err
	}
	// Covered unless the probe says otherwise, which is what makes a probe that
	// cannot be put leave the edit alone.
	covered := true
	if sops, err := exec.LookPath(sopsBinary); err == nil {
		if answer, err := sopsrule.Covers(sops, configPath, recipients, target); err == nil {
			covered = answer
		}
	}
	if covered {
		return nil
	}
	return fmt.Errorf("%s has no creation rule matching %s, so sops would refuse "+
		"to write it back and the edit would be lost. Widen path_regex to cover "+
		"it, or keep the store where the rule already looks. `faramir doctor` "+
		"reports this under `rule coverage`", rulePath, target)
}

// ruleMustNotSplitTheKey refuses an edit under a rule that splits the data key,
// or nil. The refusal `faramir reader reseal` makes, one step earlier:
// shamir_threshold means N of the rule's key groups have to come together to
// open a file, and what an edit writes back is sealed to the recipients the
// file already carried, as one group. sops writes the threshold beside that
// single group, so any one of those keys then opens the file.
func ruleMustNotSplitTheKey(rulePath string) error {
	// A rule this cannot read leaves rules empty and nothing to refuse: the same
	// file reaches sops next, and what sops says about it is the better answer.
	rules, _ := sopsrule.Load(rulePath)
	for _, rule := range rules {
		if rule.ShamirThreshold > 0 {
			return fmt.Errorf("%s sets shamir_threshold: the data key is split "+
				"across key groups, and %d of them are needed to open a file. Writing "+
				"this file back would seal it to one group holding every key, so the "+
				"edit was refused. Use sops directly for this store", rulePath, rule.ShamirThreshold)
		}
	}
	return nil
}

// RuleRecipients reads who .sops.yaml says a managed file should be encrypted
// to. One creation rule only: the shipped file has exactly one, matching any
// *.sops.yml wherever it sits. With two the answer depends on which path_regex
// a file matches, which this cannot answer, so it refuses rather than
// re-encrypting half the secrets directory to the wrong set.
func RuleRecipients(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	return RuleRecipientsFrom(body, path)
}

// RuleRecipientsFrom is ruleRecipients for a caller holding the bytes, which is
// what a command that has edited the rule and not yet written it has: a rule
// this refuses is one the file should never come to hold.
func RuleRecipientsFrom(body []byte, path string) ([]string, error) {
	rules, err := sopsrule.Parse(body, path)
	if err != nil {
		return nil, fmt.Errorf("creation rule: %w", err)
	}
	if len(rules) > 1 {
		return nil, fmt.Errorf("%s has %d creation rules, and path_regex decides which "+
			"one governs a file. Re-key each file with 'sops updatekeys'", path, len(rules))
	}
	for _, rule := range rules {
		// A split data key is refused rather than flattened: shamir_threshold means
		// N key groups have to come together to open the file, and this re-encrypts
		// to one list of recipients, so any one of them would open what took N
		// before.
		if rule.ShamirThreshold > 0 {
			return nil, fmt.Errorf("%s sets shamir_threshold: the data key is "+
				"split across key groups, and %d of them are needed to open a file. "+
				"Re-encrypting here would seal it to one group holding every key. "+
				"Re-key each file with 'sops updatekeys'",
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

// KeeperStaysAReader refuses a rule that leaves out the key this host decrypts
// with. The recipients are public keys, so the check is the public half of the
// age key against the list. Getting it wrong is not recoverable by re-running:
// the files would already be sealed to a set without the only identity on the
// host.
func KeeperStaysAReader(keyPath string, wanted []string, rulePath string) error {
	recipient, err := keygen.AgeRecipient(keyPath)
	if err != nil {
		return fmt.Errorf("age key: %w", err)
	}
	if slices.Contains(wanted, recipient) {
		return nil
	}
	return fmt.Errorf("%s does not list %s, the recipient for the key at %s. "+
		"Re-encrypting would leave a store the keeper cannot open, and the "+
		"broker would serve nothing. Add it under '- age:' first",
		rulePath, recipient, keyPath)
}

// EditRule is the one call that differs between add and rm.
func EditRule(body []byte, path, recipient string, adding bool) ([]byte, bool, error) {
	if adding {
		return sopsrule.Add(body, path, recipient)
	}
	return sopsrule.Remove(body, path, recipient)
}
