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
		// Patterns is the configured globs, Files what they named on disk.
		// Entries naming nothing are a host waiting for its secrets; entries naming
		// files that did not load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
		// UnresolvedPatterns is the entries that named nothing, which the broker
		// cannot work out for itself: the secrets directory is the keeper's to list.
		UnresolvedPatterns []string `json:"unresolved_patterns"`
		// NotRedactable is the refs the store read and the redactor refused, by ref
		// and reason.  They load and are never injected, so they are a value the
		// operator has to lengthen rather than anything about the install.
		NotRedactable map[string]string `json:"not_redactable"`
	} `json:"secrets"`
	// Policy is the socket-policy problems, which --check also exits non-zero
	// for.  Read here so a caller can tell which of the reasons it is looking at.
	Policy []string `json:"policy"`
}

// onlyNotRedactable reports whether a non-zero --check is accounted for by refs
// the redactor refused and nothing else.  --check exits 1 for several states at
// once, so the exit code alone cannot say which; every other state it fails for
// is visible in the report, and their absence is what leaves this one.
//
// The distinction earns its place because this state is not about the install.
// The store loaded, the daemons are serving, and one value is too short to
// cover: nothing an install can do, and the same answer every time it re-runs.
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

// serves reports whether the broker will run exec and redact: at least one
// managed file was read, and every file it read loaded.  The daemon's own gate,
// mirrored so a probe that runs a brokered command is skipped only when it would
// really be refused.  Not a ref count: files that are there and hold nothing
// still serve.
func (c checkReport) serves() bool {
	return len(c.Secrets.Files) > 0 && len(c.Secrets.Errors) == 0
}

// stepValidate asks the broker what it can do with what was installed.  As the
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
		// leaves no way to reach a working host.  Anything else, including a file
		// that is there and did not load, is fatal.
		if absent := report.Secrets.UnresolvedPatterns; len(absent) == len(report.Secrets.Patterns) &&
			len(absent) > 0 {
			// What it does is refuse, not run bare.  The sentence used to say the
			// opposite, which reads as an exposure an operator has to hurry out of and
			// teaches the wrong reflex for the day a value set really does fail to load.
			r.warnf("the broker is configured for %s, which %s named no file yet, "+
				"so it is serving nothing: with no value set it refuses every brokered "+
				"command rather than running one unredacted. Write the secrets directory "+
				"with sops and re-run",
				strings.Join(absent, ", "),
				map[bool]string{true: "has", false: "have"}[len(absent) == 1])
			r.step("validate", false, "no secrets yet")
			return nil
		}
		// Refs the redactor refused, and nothing else wrong.  Reported and carried
		// on from: the store loaded and the daemons are serving, the values are
		// never injected so nothing is exposed by continuing, and an install cannot
		// lengthen a secret.  Failing here ends every future `init` on this host
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
	// looking healthy.  Guarded on the resolved files rather than the patterns, no
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
	// injection relies on.  Nothing errors.
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
	// a brokered command gets.  The daemon comes up without a loaded key and lets
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
