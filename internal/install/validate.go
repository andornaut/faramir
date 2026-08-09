package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// checkReport is the part of `faramir-broker --check` this reads back.  Only
// the fields it acts on: the rest is passed through to the operator as the
// command's own output.
type checkReport struct {
	Secrets struct {
		Count int `json:"count"`
		// Patterns is [secrets] files as configured, Files is what that named on
		// disk.  A glob makes them differ, and the difference is the whole
		// question this step asks: entries that name nothing are a host waiting
		// for its store, entries that name files which did not load are a fault.
		Patterns []string `json:"patterns"`
		Files    []string `json:"files"`
		Errors   []string `json:"errors"`
	} `json:"secrets"`
}

// stepValidate asks the broker what it can actually do with what was installed.
//
// Run as the broker's own uid, not as root: --check opens the SSH keys and the
// secrets files itself, and root reads what the broker cannot.  A key left
// root-owned would otherwise pass here and leave every brokered command unable
// to authenticate against any host.
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
	// The report is printed on stdout whether the gate passed or not, so it is
	// read before the exit code is judged: what the broker could not load is the
	// thing that decides whether this is a failure or a host that has not been
	// given its secrets yet.
	var report checkReport
	if jsonErr := json.Unmarshal([]byte(out), &report); jsonErr != nil {
		if checkErr != nil {
			return fmt.Errorf("the installed config does not work for %s: %w",
				r.layout.BrokerUser, checkErr)
		}
		return fmt.Errorf("could not read the --check report: %w", jsonErr)
	}
	if checkErr != nil {
		// A configured file that has not been created yet is the ordinary state
		// of a host whose store is written after it is provisioned, and it is
		// what every first install looks like.  The running broker still treats
		// it as a load failure and refuses to serve, which is the property that
		// keeps a silent gap in redaction from existing; but failing the install
		// over it leaves no way to reach a working host, because the next run
		// fails in the same place.
		//
		// Anything else is fatal, including a file that is there and could not be
		// read or decrypted.
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

	// The keeper decrypts sops and nothing else, so a credential held anywhere
	// else is absent from the value set, and a value absent from the set is
	// neither injectable nor redacted.  Zero refs from a store that exists is
	// therefore a broker that is running and protecting nothing, which is
	// indistinguishable from a healthy install unless something says so.
	//
	// Guarded rather than unconditional, and on the resolved files rather than
	// the patterns: no files at all is what a first install looks like, its
	// store directory created and still empty.
	if len(report.Secrets.Files) > 0 && report.Secrets.Count == 0 {
		return fmt.Errorf("the broker read %s and loaded no refs. Nothing is "+
			"injectable and nothing is redacted: a command that prints a credential "+
			"prints it in plaintext. %s",
			strings.Join(report.Secrets.Files, ", "), loadErrorDetail(report.Secrets.Errors))
	}

	// Ansible loads every .yml under group_vars/ and host_vars/ as a vars file,
	// and a sops file is valid YAML: it binds each var to its ENC[...]
	// ciphertext, and a name sorting after vars.yml also overwrites the
	// environment lookup the broker's injection relies on.  Nothing errors and
	// no task fails; hosts get configured with the ciphertext of a credential in
	// place of the credential.
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

	// Asked through the broker rather than read off disk, because what matters
	// is what a brokered command gets: the executor's uid can use the agent but
	// cannot read the key, so this is the only place the answer is visible.  The
	// broker loads its keys at startup and only warns when none of them load, so
	// a missing or unreadable key leaves every socket active and every playbook
	// unable to reach a single managed host.
	if r.opts.SSHKey != "" {
		out, agentErr := r.command(filepath.Join(r.layout.BinDir, "faramir"),
			"run", "--quiet", "--", "ssh-add", "-l")
		// The error carries stderr, which is where the reason is.  Dropping it
		// reports every way this can fail, including a working agent asked from a
		// directory the broker cannot stat, as "holds no usable key ()".
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

// unresolved is the configured entries that name no file on disk.
//
// Expanded here rather than read out of the broker's error text: "named nothing
// yet" and "named a file that would not load" are the two cases this has to
// tell apart, and only the first is a host waiting for its secrets to be
// written.  This runs as root, which the broker does not, so it can expand a
// pattern the broker could only report as written.
//
// A missing literal path is the same case: Glob finds nothing for it either, so
// one rule covers both and a host provisioned before its store still installs.
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
