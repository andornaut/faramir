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
		report.addf("sops config", StatusWarn, "no %s, so sops has no creation rule "+
			"and refuses to encrypt a new file in the secrets directory", current)
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
			report.unaskedf("sops config", 1, "%s could not be read (%v), so who "+
				"can decrypt the secrets directory went unchecked. Run doctor as root", path, err)
			return
		}
		report.addf("sops config", StatusFailed, "%s does not parse (%v), so who can "+
			"decrypt the secrets directory is unknown here. sops has to read this file too", path, err)
		return
	}
	if len(listed) == 0 {
		report.addf("sops config", StatusWarn, "%s lists no age recipient, so sops "+
			"encrypts a new file in the secrets directory to nobody and refuses", path)
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
			report.addf("sops config", StatusFailed, "%s is missing, so %s can "+
				"decrypt nothing and every managed value is unreadable. Restore the key from "+
				"backup; a key the store is sealed to cannot be re-minted",
				keyPath, opts.KeeperUser)
			return
		}
		report.unaskedf("sops config", 1, "%s lists %s, and whether %s is among "+
			"them went unchecked: %v. Run doctor as root", path, strings.Join(listed, ", "),
			keyPath, err)
		return
	}
	// Warn, not failed: the values already in the secrets directory still decrypt,
	// so this is a host that works today and cannot take a new value tomorrow.
	if !slices.Contains(listed, keeper) {
		report.addf("sops config", StatusWarn, "%s lists %s, none of which is %s's recipient (%s), so every value encrypted from "+
			"now on is one %s cannot decrypt. Put it back with `sudo faramir reader add %s`, "+
			"which re-seals the store to it",
			path, strings.Join(listed, ", "), keyPath, keeper, opts.KeeperUser, keeper)
		return
	}
	report.addf("sops config", StatusOK, "%s, %d recipient(s) including %s's",
		path, len(listed), opts.KeeperUser)
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
		// The error names what to do, including the rotation a private half needs,
		// so it is carried rather than summarised.
		report.addf("sops config", StatusFailed, "%s lists something sops will not "+
			"take as a recipient: %v", path, err)
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
		report.unaskedf("rule coverage", 1, "the managed store could not be read, so "+
			"which files %s has to cover is unknown here", rulePath)
		return
	}
	// filepath.Glob reports a directory it cannot list as no matches and no
	// error, so a caller who cannot read one pattern's directory would get a
	// confident answer about half a store. What did resolve is still checked.
	unlistable := unlistableDirs(opts.SecretsPatterns)
	if len(unlistable) > 0 {
		report.unaskedf("rule coverage", 1, "the directories the managed store "+
			"names cannot be listed by this account (%s), so the managed files under them "+
			"went unchecked. Run doctor as root",
			strings.Join(unlistable, ", "))
	}
	managed, _, _ := keeper.Resolve(opts.SecretsPatterns)
	if len(managed) == 0 {
		if len(unlistable) > 0 {
			// Nothing resolved and a directory was unreadable, so the count above
			// stands on its own: reporting nothing to cover would read as an empty
			// store.
			return
		}
		report.addf("rule coverage", StatusNA, "no managed file matches [secret] "+
			"patterns yet, so there is nothing for %s to cover", rulePath)
		return
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		report.unaskedf("rule coverage", 1, "sops is not on this PATH, and it "+
			"decides which rule governs a file: %v", err)
		return
	}
	// The rule's own recipients, named on the command line, so what is asked is
	// whether a rule matches rather than whether its keys work.
	recipients, err := sopsrule.AllRecipients(rulePath)
	if err != nil {
		report.unaskedf("rule coverage", 1, "%s could not be read, so which files it "+
			"covers went unchecked: %v", rulePath, err)
		return
	}
	covered := 0
	for _, target := range managed {
		switch matched, err := sopsrule.Covers(sops, rulePath, recipients, target); {
		case err != nil:
			report.unaskedf("rule coverage", 1, "whether %s covers %s went unchecked: %v",
				rulePath, target, err)
		case matched:
			covered++
		default:
			report.addf("rule coverage", StatusFailed, "%s has no creation rule matching %s, so `faramir vault edit` and `faramir reader "+
				"reseal` cannot write it back. Widen path_regex to reach it, or keep the store "+
				"where the rule looks", rulePath, target)
		}
	}
	// Only where every file was asked about and answered yes: an unreadable
	// directory would otherwise be claimed as covered.
	if covered == len(managed) && len(unlistable) == 0 {
		report.addf("rule coverage", StatusOK, "%s covers all %d managed file(s)",
			rulePath, covered)
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
		report.unaskedf("recipient drift", 1, "the managed store could not be read, "+
			"so which files %s has to agree with is unknown here", rulePath)
		return
	}
	wanted, err := sopsrule.AllRecipients(rulePath)
	if err != nil {
		report.unaskedf("recipient drift", 1, "%s could not be read, so what the "+
			"store should be sealed to is unknown: %v", rulePath, err)
		return
	}
	managed, _, _ := keeper.Resolve(opts.SecretsPatterns)
	if len(managed) == 0 {
		report.addf("recipient drift", StatusNA, "no managed file matches [secret] "+
			"patterns yet, so nothing can disagree with %s", rulePath)
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
			report.unaskedf("recipient drift", 1, "%s could not be read, so whether "+
				"it agrees with %s went unchecked: %v", target, rulePath, err)
			continue
		}
		checked++
		if sopsrule.Same(was, wanted) {
			continue
		}
		drifted++
		report.addf("recipient drift", StatusFailed, "%s is sealed to %s while "+
			"%s names %s, so a key the rule grants may not open it and a key it no longer "+
			"grants may. Run: sudo faramir reader reseal",
			target, strings.Join(was, ", "), rulePath, strings.Join(wanted, ", "))
	}
	// Only where every file sealed to anything was reached and agreed. With none
	// sealed there is nothing to pass.
	if drifted == 0 && checked > 0 && checked+sealedToNothing == len(managed) {
		report.addf("recipient drift", StatusOK, "all %d encrypted file(s) are sealed "+
			"to what %s names", checked, rulePath)
	}
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
