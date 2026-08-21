package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// checkReport is the part of `faramir-broker --check` this acts on; the rest is
// passed through as the command's own output.
type checkReport struct {
	Secrets struct {
		Count int `json:"count"`
		// Patterns is the configured globs, Files what they named on disk. Entries
		// naming nothing are a host waiting for its secrets; files that did not
		// load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
		// UnresolvedPatterns is the entries that named nothing, which the broker
		// cannot work out for itself: the secrets directory is the keeper's to
		// list.
		UnresolvedPatterns []string `json:"unresolved_patterns"`
		// NotRedactable is the refs the store read and the redactor refused, by ref
		// and reason. They load and are never injected, so each is a value to
		// lengthen rather than anything about the install.
		NotRedactable map[string]string `json:"not_redactable"`
		// Links is how many of Count came from [[secret.link]] entries rather than
		// from a managed file. A count, not the paths, which are the operator's
		// own files. An install whose whole value set is linked keeps no store,
		// and the daemon serves it.
		Links int `json:"links"`
	} `json:"secrets"`
	// Policy is the socket-policy problems, which --check also exits non-zero
	// for. Read here so a caller can tell which reason it is looking at.
	Policy []string `json:"policy"`
}

// onlyNotRedactable reports whether a non-zero --check is accounted for by refs
// the redactor refused and nothing else: --check exits 1 for several states, and
// every other one is visible in the report. The distinction earns its place
// because this state is not about the install: the store loaded, the daemons
// are serving, and one value is too short to cover.
func (c checkReport) onlyNotRedactable() bool {
	return len(c.Secrets.NotRedactable) > 0 &&
		len(c.Policy) == 0 &&
		len(c.Secrets.Errors) == 0 &&
		len(c.Secrets.UnresolvedPatterns) == 0 &&
		c.Secrets.Count > 0
}

// refusedRefs is the refused refs and their reasons, ordered, for a message.
func (c checkReport) refusedRefs() string {
	out := make([]string, 0, len(c.Secrets.NotRedactable))
	for ref, reason := range c.Secrets.NotRedactable {
		out = append(out, fmt.Sprintf("%s (%s)", ref, reason))
	}
	slices.Sort(out)
	return strings.Join(out, ", ")
}

// serves reports whether the broker will run exec and redact: something was
// read, and every file it read loaded. Store.Unreadable is the daemon's own
// gate, mirrored here so a probe that runs a brokered command is skipped only
// when it would really be refused.
//
// Links as well as files, because a [[secret.link]] entry fills the value set
// without the keeper contributing anything, and an install whose whole set is
// linked keeps no managed file at all. Counting files alone skipped the probes
// that check redaction on exactly those hosts, and gave the broker refusing as
// the reason when it was serving.
//
// Not a ref count: files that hold nothing still serve, the daemon asking what
// was read rather than what was in it. Configured links rather than resolved
// ones, which the report does not carry: a link whose file has gone reads as
// serving here and the probe then fails on it, which names the fault. The other
// direction skips the probe and reports nothing.
func (c checkReport) serves() bool {
	return (len(c.Secrets.Files) > 0 || c.Secrets.Links > 0) &&
		len(c.Secrets.Errors) == 0
}

// stepValidate asks the broker what it can do with what was installed. As the
// broker's own uid, not root: --check opens the SSH keys and the secrets files
// itself, and root reads what the broker cannot.
func (r *runner) stepValidate() error {
	if r.opts.DryRun {
		r.skip("validate", "dry run")
		return nil
	}
	if !systemdRunning() {
		r.skip("validate", "systemd is not running, so nothing is serving")
		return nil
	}
	broker := filepath.Join(r.layout.BinDir, "faramir")
	out, checkErr := r.command("runuser", "-u", r.layout.BrokerUser, "--",
		broker, "broker", "-c", r.layout.ConfigFile, "--check")
	// Read before the exit code is judged: what the broker could not load decides
	// whether this is a failure or a host without its secrets yet.
	var report checkReport
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		if checkErr != nil {
			return fmt.Errorf("the installed config does not work for %s: %w",
				r.layout.BrokerUser, checkErr)
		}
		return fmt.Errorf("could not read the --check report: %w", jsonErr)
	}
	if checkErr != nil {
		// A configured file not yet created is what every first install looks like.
		// The running broker still refuses to serve, but failing the install over it
		// leaves no way to reach a working host. Anything else, including a file
		// that is there and did not load, is fatal.
		if absent := report.Secrets.UnresolvedPatterns; len(absent) == len(report.Secrets.Patterns) &&
			len(absent) > 0 {
			// What it does is refuse, not run bare. Said that way round: a warning
			// that reads as an exposure teaches the wrong reflex for the day a value
			// set really does fail to load.
			r.warnf("the broker is configured for %s, which %s named no file yet, "+
				"so it is serving nothing: with no value set it refuses every brokered "+
				"command rather than running one unredacted. Write the secrets directory "+
				"with sops and re-run",
				strings.Join(absent, ", "),
				map[bool]string{true: "has", false: "have"}[len(absent) == 1])
			r.step("validate", false, "no secrets yet")
			return nil
		}
		// Refs the redactor refused, and nothing else wrong. Reported and carried
		// on from: the store loaded and the daemons are serving, the values are
		// never injected so nothing is exposed by continuing, and an install cannot
		// lengthen a secret. Failing here ends every future `init` on this host
		// the same way, including the upgrade that would carry a fix.
		if report.onlyNotRedactable() {
			r.warnf("%d ref(s) are too short for [secret] min_length, so they are "+
				"never injected and never redacted: %s. Lengthen them with `faramir "+
				"edit`; everything else on this host is installed and serving",
				len(report.Secrets.NotRedactable), report.refusedRefs())
			r.step("validate", false, "installed; refs to lengthen")
			return nil
		}
		return fmt.Errorf("the installed config does not work for %s: %w\n"+
			"A [secret] file named there is one the broker could not load. A ref "+
			"reported under not_redactable needs lengthening instead",
			r.layout.BrokerUser, checkErr)
	}

	// A value absent from the set is neither injectable nor redacted, so zero refs
	// from a secrets directory that exists is a broker protecting nothing while
	// looking healthy. Guarded on the resolved files rather than the patterns, no
	// files at all being what a first install looks like.
	if len(report.Secrets.Files) > 0 && report.Secrets.Count == 0 {
		return fmt.Errorf("the broker read %s and loaded no refs. Nothing is "+
			"injectable and nothing is redacted: a command that prints a credential "+
			"prints it in plaintext. %s",
			strings.Join(report.Secrets.Files, ", "), loadErrorDetail(report.Secrets.Errors))
	}

	// Ansible loads every .yml under group_vars/ and host_vars/ as a vars file,
	// and a sops file is valid YAML: each var binds to its ENC[...] ciphertext,
	// and a name sorting after vars.yml overwrites the environment lookup the
	// injection relies on. Nothing errors.
	for _, file := range report.Secrets.Files {
		if strings.Contains(file, "/group_vars/") || strings.Contains(file, "/host_vars/") {
			return fmt.Errorf("%s is under group_vars/ or host_vars/, which Ansible "+
				"auto-loads. Every var would resolve to its ENC[...] ciphertext "+
				"instead of the injected value, silently. Move it to %s",
				file, r.layout.SecretsDir())
		}
	}

	r.brokerChecked = true
	r.brokerLoadedRefs = report.Secrets.Count
	r.step("validate", false, fmt.Sprintf("%d ref(s) from %d file(s)",
		report.Secrets.Count, len(report.Secrets.Files)))

	// Asked through the broker rather than read off disk, what matters being what
	// a brokered command gets. The daemon comes up without a loaded key and lets
	// SSH fail where it is used, so nothing else would say the key is missing at
	// install time. Gated on the key that reached disk rather than on --ssh-key,
	// which is a relocation and empty on most runs.
	//
	// Skipped while the broker is refusing, which is what a first install looks
	// like: this probe would report the refusal as an SSH fault.
	if r.sshKey != "" && !report.serves() {
		r.warnf("the broker has read no managed file yet, so it refuses brokered " +
			"commands and what its ssh-agent holds could not be asked. Write a " +
			"secret, then: faramir doctor")
		r.step("broker ssh agent", false, "not asked")
	}
	if r.sshKey != "" && report.serves() {
		out, agentErr := r.command(filepath.Join(r.layout.BinDir, "faramir"),
			"run", "--quiet", "--", "ssh-add", "-l")
		// The error carries stderr, where the reason is; dropping it reports every
		// failure as "holds no usable key ()".
		if agentErr != nil {
			return fmt.Errorf("could not ask the broker what its agent holds: %w\n"+
				"A brokered command runs where its caller was, so this also fails "+
				"when init is run from a directory %s cannot enter",
				agentErr, r.layout.BrokerUser)
		}
		if !strings.Contains(out, "SHA256") {
			return fmt.Errorf("the broker's ssh-agent holds no usable key (%s), "+
				"though [ssh] key names %s. Brokered commands can reach no managed "+
				"host. Check that %s can read it and that it is not "+
				"passphrase-protected, then restart faramir-broker",
				strings.TrimSpace(out), r.sshKey, r.layout.BrokerUser)
		}
		r.step("broker ssh agent", false, "holds a usable key")
	}

	return nil
}

func loadErrorDetail(errors []string) string {
	if len(errors) == 0 {
		return "The broker reported no load error, so the file parsed and is empty " +
			"rather than unreadable."
	}
	return "Load errors: " + strings.Join(errors, "; ")
}

// storeHolds is what the value set is made of where no managed file resolved,
// which is what separates a host keeping its secrets in links alone from one
// whose store went missing. Serving nothing is said plainly: exec and redact
// are refused until something loads.
func (c checkReport) storeHolds() string {
	switch {
	case c.Secrets.Links > 0 && c.Secrets.Count > c.Secrets.Links:
		return fmt.Sprintf("%d ref(s) are served, %d of them from %s",
			c.Secrets.Count, c.Secrets.Links, linkEntries(c.Secrets.Links))
	case c.Secrets.Links > 0:
		return "the whole value set is " + linkEntries(c.Secrets.Links)
	default:
		return "nothing is served, and exec and redact are refused until something is"
	}
}

// linkNote names the linked share of a value set that also has managed files,
// so a count that changed says which half it changed in.
func (c checkReport) linkNote() string {
	if c.Secrets.Links == 0 {
		return ""
	}
	return " and " + linkEntries(c.Secrets.Links)
}

// storeFinding is what the `secrets store` check reports: what the store holds,
// and whether anything about it is wrong.
//
// Keeping no managed file is a valid install rather than a fault. A
// [[secret.link]] entry fills the value set on its own, and a host that has not
// written its first secret is every install on its first day, which is why
// `init` warns there and carries on. The two sibling checks over links and
// refused paths already report having none as ok; this one failing was the
// outlier.
func storeFinding(c checkReport) (Status, string) {
	switch {
	case len(c.Secrets.Errors) > 0:
		// First, and on its own: the daemon refuses every redacted op while one
		// file did not load, whatever else did, so a ref count beside it would
		// describe a store that is not being served.
		return StatusFailed, loadErrorDetail(c.Secrets.Errors)
	case len(c.Secrets.Patterns) == 0 && c.Secrets.Links == 0:
		return StatusFailed, "no managed sops files and no [[secret.link]] entries " +
			"are configured, so nothing is injectable and nothing is redacted"
	case len(c.Secrets.UnresolvedPatterns) > 0:
		// A warning rather than a failure, because this cannot tell a host that
		// keeps no store from one whose store went missing: the pattern is derived
		// from the config directory, so it is on every install and names nothing
		// until a first file is written. What is served is reported beside it,
		// that being what tells an operator which of the two they are looking at.
		// The entries carry their own reason, "matched no files" or the stat error
		// a literal path gave, so this adds none.
		return StatusWarn, fmt.Sprintf("%s, so %s. Either the secrets have not been "+
			"written yet, or they are on a filesystem that is not mounted",
			strings.Join(c.Secrets.UnresolvedPatterns, "; "), c.storeHolds())
	case c.Secrets.Count == 0:
		return StatusFailed, fmt.Sprintf("read %s and loaded no refs",
			strings.Join(c.Secrets.Files, ", "))
	}
	return StatusOK, fmt.Sprintf("%d ref(s) from %d file(s)%s",
		c.Secrets.Count, len(c.Secrets.Files), c.linkNote())
}

// linkEntries names a count of link entries, singular where there is one: this
// reads in the middle of a sentence an operator is being told something by.
func linkEntries(n int) string {
	if n == 1 {
		return "1 [[secret.link]] entry"
	}
	return fmt.Sprintf("%d [[secret.link]] entries", n)
}
