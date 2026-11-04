package doctor

import (
	"errors"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/keygen"
	"github.com/andornaut/faramir/internal/sopsrule"
)

// diagnoseSopsConfig examines the creation rule the install writes: who it
// seals to, which of the managed files it governs, and whether the store still
// matches it.
func diagnoseSopsConfig(report *Report, opts Options) {
	layout := hostlayout.Layout{ConfigDir: opts.ConfigDir}
	current := layout.SopsConfigPath()
	if !hostfs.Exists(current) {
		report.addf("sops config", StatusWarn, "no %s; sops cannot encrypt a new "+
			"managed file", current)
		return
	}
	diagnoseSopsRecipients(report, opts, current)
	diagnoseSopsRuleCoverage(report, opts, current)
	diagnoseRecipientDrift(report, opts, current)
}

// diagnoseSopsRecipients answers who can decrypt what the secrets directory
// will hold next. The keeper's own recipient has to be there: without it the
// broker cannot read the next value and still starts and reports healthy. init
// writes this file once, so a key restored or re-minted leaves the rule naming
// the recipient it used to have.
func diagnoseSopsRecipients(report *Report, opts Options, path string) {
	listed, err := sopsrule.AllRecipients(path)
	if err != nil {
		// An unreadable file and one that does not parse are different faults
		// with different remedies, and only the second is sops's concern too.
		if errors.Is(err, fs.ErrPermission) {
			report.unaskedf("sops config", 1, "%s unreadable; run doctor as root\n%v", path, err)
			return
		}
		report.addf("sops config", StatusFailed, "%s does not parse\n%v", path, err)
		return
	}
	if len(listed) == 0 {
		report.addf("sops config", StatusWarn, "%s lists no age recipient", path)
		return
	}
	// The file is 0644, so root can edit it directly, and nothing on that path
	// looks at what was typed: `faramir reader add` validates a key and a hand
	// edit does not. A private half pasted here is the key to the secrets
	// directory, readable by every account. Asked first, the rest assuming
	// entries that at least parse as recipients.
	if !recipientsAreWellFormed(report, listed, path) {
		return
	}
	// The key is 0400 and the keeper's, so this answers only under sudo, and is
	// reported as unchecked rather than as a pass.
	keyPath := filepath.Join(opts.ConfigDir, "age.key")
	keeper, err := keygen.AgeRecipient(keyPath)
	if err != nil {
		// A key that is not there is not a privilege problem, and telling root to
		// re-run as root would send the operator in a circle: the keeper can
		// decrypt nothing until the key is restored.
		if errors.Is(err, fs.ErrNotExist) {
			report.addf("sops config", StatusFailed, "%s is missing; restore it "+
				"from backup", keyPath)
			return
		}
		report.unaskedf("sops config", 1, "whether %s lists %s not checked; run "+
			"doctor as root\n%v", path, keyPath, err)
		return
	}
	// Warn, not failed: the values already in the secrets directory still decrypt,
	// so this is a host that works today and cannot take a new value tomorrow.
	if !slices.Contains(listed, keeper) {
		report.addf("sops config", StatusWarn, "%s omits %s's recipient %s; run "+
			"`sudo faramir reader add %s`\nlisted: %s",
			path, keyPath, keeper, keeper, strings.Join(listed, ", "))
		return
	}
	report.addf("sops config", StatusOK, "%s, %d recipient(s)", path, len(listed))
}

// recipientsAreWellFormed reports every entry sops would refuse, and whether
// there were none. Failed rather than warned: sops encrypts nothing into this
// directory while one is there.
func recipientsAreWellFormed(report *Report, listed []string, path string) bool {
	ok := true
	for _, recipient := range listed {
		err := keygen.ValidateRecipient(recipient)
		if err == nil {
			continue
		}
		ok = false
		// A private key in the file is already readable by every account, so its
		// fix is a rotation, which the refusal written for a paste cannot name.
		// The refusal follows as the detail either way.
		if errors.Is(err, keygen.ErrPrivateHalf) {
			report.addf("sops config", StatusFailed, "%s lists a private key; replace it "+
				"with its public key and rotate the key\n%v", path, err)
			continue
		}
		report.addf("sops config", StatusFailed, "%s lists a recipient sops will not "+
			"take\n%v", path, err)
	}
	return ok
}

// diagnoseSopsRuleCoverage asks whether the creation rules reach every managed
// file, which decides whether `faramir vault edit` and `faramir reader
// reseal` can write one back: sops refuses a file no rule covers.
//
// Each file is put to sops as an encryption of a throwaway document under its
// own name, rather than matching path_regex here: a second implementation of
// that match is free to disagree with sops.
func diagnoseSopsRuleCoverage(report *Report, opts Options, rulePath string) {
	if len(opts.SecretsPatterns) == 0 {
		report.unaskedf("rule coverage", 1, "managed store unreadable; %s not "+
			"checked", rulePath)
		return
	}
	managed, complete := resolveStore(report, "rule coverage", opts.SecretsPatterns)
	if len(managed) == 0 {
		return
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		report.unaskedf("rule coverage", 1, "sops not on PATH")
		return
	}
	// The rule's own recipients, named on the command line, so what is asked is
	// whether a rule matches rather than whether its keys work.
	recipients, err := sopsrule.AllRecipients(rulePath)
	if err != nil {
		report.unaskedf("rule coverage", 1, "%s unreadable\n%v", rulePath, err)
		return
	}
	covered := 0
	for _, target := range managed {
		switch matched, err := sopsrule.Covers(sops, rulePath, recipients, target); {
		case err != nil:
			report.unaskedf("rule coverage", 1, "whether %s covers %s not checked\n%v",
				rulePath, target, err)
		case matched:
			covered++
		default:
			report.addf("rule coverage", StatusFailed, "%s has no creation rule "+
				"matching %s; widen its path_regex", rulePath, target)
		}
	}
	// Only where every file was asked about and answered yes: an unreadable
	// directory would otherwise be claimed as covered.
	if covered == len(managed) && complete {
		report.addf("rule coverage", StatusOK, "%d managed file(s) covered", covered)
	}
}

// diagnoseRecipientDrift asks whether every managed file is sealed to what the
// rule names. A store passes `sops config` and `rule coverage` while its
// ciphertext is sealed to a set the rule no longer names: a reseal that failed
// partway, or a rule changed by hand and never applied. Nothing fails in that
// state until somebody reaches for a value with a key they were told they had.
//
// The recipients sops writes into a file are cleartext, so this needs no key,
// only the ability to read the file.
func diagnoseRecipientDrift(report *Report, opts Options, rulePath string) {
	if len(opts.SecretsPatterns) == 0 {
		report.unaskedf("recipient drift", 1, "managed store unreadable; %s not "+
			"checked", rulePath)
		return
	}
	wanted, err := sopsrule.AllRecipients(rulePath)
	if err != nil {
		report.unaskedf("recipient drift", 1, "%s unreadable\n%v", rulePath, err)
		return
	}
	managed, complete := resolveStore(report, "recipient drift", opts.SecretsPatterns)
	if len(managed) == 0 {
		return
	}
	drifted, checked, sealedToNothing := 0, 0, 0
	for _, target := range managed {
		was, err := sopsrule.SealedTo(target)
		switch {
		// Not drift: a file sealed to nothing is unencrypted or sealed to something
		// other than age, which `rule coverage` and the broker's --check report.
		case errors.Is(err, sopsrule.ErrNoRecipients):
			sealedToNothing++
			continue
		// Unasked rather than failed: a caller who cannot open the file has learned
		// nothing about whether it agrees.
		case err != nil:
			report.unaskedf("recipient drift", 1, "%s unreadable\n%v", target, err)
			continue
		}
		checked++
		if sopsrule.Same(was, wanted) {
			continue
		}
		drifted++
		report.addf("recipient drift", StatusFailed, "%s is not sealed to what "+
			"%s names; run `sudo faramir reader reseal`\nsealed to: %s\nrule names: %s",
			target, rulePath, strings.Join(was, ", "), strings.Join(wanted, ", "))
	}
	// Only where every file sealed to anything was reached and agreed, in a store
	// listed in full. With none sealed there is nothing to pass.
	if drifted == 0 && checked > 0 && checked+sealedToNothing == len(managed) && complete {
		report.addf("recipient drift", StatusOK, "%d file(s) sealed as %s names",
			checked, rulePath)
	}
}

// resolveStore resolves the managed files for check and reports what the
// resolution could not see, returning the files and whether every directory
// behind the patterns was listed. filepath.Glob reports a directory it cannot
// list as no matches and no error, so a caller who cannot read one would
// otherwise get a confident answer about half a store, or call a full one
// empty. What did resolve is still the caller's to check, and an incomplete
// store does not pass. A store that lists in full and holds nothing is not
// applicable.
func resolveStore(report *Report, check string, patterns []string) ([]string, bool) {
	unlistable := unlistableDirs(patterns)
	if len(unlistable) > 0 {
		report.unaskedf(check, 1, "cannot list %s; run doctor as root",
			strings.Join(unlistable, ", "))
	}
	managed, _, _ := keeper.Resolve(patterns)
	if len(managed) == 0 && len(unlistable) == 0 {
		report.addf(check, StatusNA, "no managed file yet")
	}
	return managed, len(unlistable) == 0
}

// unlistableDirs names the directories behind these patterns that this account
// cannot read, which is the difference between a store with no files in it and
// a store this caller cannot see into.
func unlistableDirs(patterns []string) []string {
	var out []string
	for _, pattern := range patterns {
		dir := filepath.Dir(pattern)
		handle, err := os.Open(dir)
		if err != nil {
			// Only a directory that is there and closed to this account; an absent one
			// is a store not written yet.
			if os.IsPermission(err) && !slices.Contains(out, dir) {
				out = append(out, dir)
			}
			continue
		}
		_, err = handle.Readdirnames(1)
		_ = handle.Close()
		if err != nil && !errors.Is(err, io.EOF) && !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	return out
}
