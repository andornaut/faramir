package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// checkReport is the part of `faramir-broker --check` this acts on; the rest is
// passed through as the command's own output.
type checkReport struct {
	Secrets struct {
		Count int `json:"count"`
		// Patterns is [secrets] files as configured, Files what it named on
		// disk.  Entries naming nothing are a host waiting for its store;
		// entries naming files that did not load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
	} `json:"secrets"`
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
	// Read before the exit code is judged: what the broker could not load
	// decides whether this is a failure or a host without its secrets yet.
	var report checkReport
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		if checkErr != nil {
			return fmt.Errorf("the installed config does not work for %s: %w",
				r.layout.BrokerUser, checkErr)
		}
		return fmt.Errorf("could not read the --check report: %w", jsonErr)
	}
	if checkErr != nil {
		// A configured file not yet created is what every first install looks
		// like.  The running broker still refuses to serve, but failing the
		// install over it leaves no way to reach a working host.  Anything
		// else, including a file that is there and did not load, is fatal.
		if absent := unresolved(report.Secrets.Patterns); len(absent) == len(report.Secrets.Patterns) &&
			len(absent) > 0 {
			r.warn("the broker is configured for %s, which %s named no file yet, "+
				"so it is serving nothing and redacting nothing. Write the store with "+
				"sops and re-run; until then every brokered command runs unredacted",
				strings.Join(absent, ", "),
				map[bool]string{true: "has", false: "have"}[len(absent) == 1])
			r.step("validate", false, "no store yet")
			return nil
		}
		return fmt.Errorf("the installed config does not work for %s: %w\n"+
			"A [secrets] file named there is one the broker could not load. A ref "+
			"reported under not_redactable needs lengthening instead",
			r.layout.BrokerUser, checkErr)
	}

	// A value absent from the set is neither injectable nor redacted, so zero
	// refs from a store that exists is a broker protecting nothing while looking
	// healthy.  Guarded on the resolved files rather than the patterns, no files
	// at all being what a first install looks like.
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

	// Asked through the broker rather than read off disk, what matters being
	// what a brokered command gets.  The broker only warns when no key loads, so
	// a missing one leaves every socket active and every playbook unable to
	// reach a host.
	if r.opts.SSHKey != "" {
		out, agentErr := r.command(filepath.Join(r.layout.BinDir, "faramir"),
			"run", "--quiet", "--", "ssh-add", "-l")
		// The error carries stderr, where the reason is; dropping it reports
		// every failure as "holds no usable key ()".
		if agentErr != nil {
			return fmt.Errorf("could not ask the broker what its agent holds: %w\n"+
				"A brokered command runs where its caller was, so this also fails "+
				"when init is run from a directory %s cannot enter",
				agentErr, r.layout.BrokerUser)
		}
		if !strings.Contains(out, "SHA256") {
			return fmt.Errorf("the broker's ssh-agent holds no usable key (%s). "+
				"Brokered commands can reach no managed host. Check that [ssh] keys "+
				"in %s or its config.d names %s, then restart faramir-broker",
				strings.TrimSpace(out), r.layout.ConfigFile, r.opts.SSHKey)
		}
		r.step("broker ssh agent", false, "holds a usable key")
	}

	return nil
}

// unresolved is the configured entries that name no file on disk.  Expanded
// here rather than read out of the broker's error text, "named nothing yet" and
// "named a file that would not load" being the two cases to tell apart; this
// runs as root, so it can expand a pattern the broker could only report as
// written.  A missing literal path is the same case.
func unresolved(patterns []string) []string {
	var absent []string
	for _, pattern := range patterns {
		matches, err := filepath.Glob(pattern)
		if err != nil || len(matches) == 0 {
			absent = append(absent, pattern)
		}
	}
	return absent
}

func loadErrorDetail(errors []string) string {
	if len(errors) == 0 {
		return "The broker reported no load error, so the file parsed and is empty " +
			"rather than unreadable."
	}
	return "Load errors: " + strings.Join(errors, "; ")
}
