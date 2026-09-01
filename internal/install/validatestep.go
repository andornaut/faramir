package install

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/brokercheck"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/runcmd"
)

// stepValidate asks the broker what it can do with what was installed. As the
// broker's own uid, not root: --check opens the SSH keys and the secrets files
// itself, and root reads what the broker cannot.
func (r *runner) stepValidate() error {
	if r.opts.DryRun {
		r.skip("validate", "dry run")
		return nil
	}
	if !hostunit.Running() {
		r.skip("validate", "systemd is not running, so nothing is serving")
		return nil
	}
	broker := filepath.Join(r.layout.BinDir, "faramir")
	out, checkErr := runcmd.Output("runuser", "-u", r.layout.BrokerUser, "--",
		"env", "FARAMIR_CONFIG="+r.layout.ConfigFile, broker, "broker", "--check")
	// Read before the exit code is judged: what the broker could not load decides
	// whether this is a failure or a host without its secrets yet.
	var report brokercheck.CheckReport
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
		// leaves no way to reach a working host. What is left is sorted by what it
		// costs to leave standing: a managed file that is there and did not load is
		// fatal, the broker withholding every command's output while it stands,
		// while a linked ref or a value the redactor refused is one credential the
		// broker names and refuses on its own, and is reported instead.
		if report.NoSecretsYet() {
			absent := report.Secrets.UnresolvedPatterns
			// What it does is refuse, not run bare. Said that way round: a warning
			// that reads as an exposure teaches the wrong reflex for the day a value
			// set really does fail to load.
			r.warnf("the broker is configured for %s, which %s named no file yet, so it is serving "+
				"nothing and refuses every brokered command. Write the secrets directory with "+
				"sops and re-run",
				strings.Join(absent, ", "),
				map[bool]string{true: "has", false: "have"}[len(absent) == 1])
			r.step("validate", false, "no secrets yet")
			return nil
		}
		// Links that did not load. Reported and carried on from, for the reason
		// the entry is scoped to its own ref in the first place: a link is one ref
		// by construction, so the broker refuses that ref and serves every other
		// one, and an install that stopped here would answer a fault in one
		// credential by leaving the host without the config this run had already
		// written. That is the same argument the refused refs below make, and it
		// binds harder here: the file belongs to another tool, so `init` cannot
		// write it, and failing brings the repair no closer.
		//
		// It is not passed over. `faramir status` exits non-zero naming the ref
		// and `faramir doctor` fails on it, so a host in this state is not one
		// anything calls healthy, and the remedies are named here rather than
		// attempted.
		if report.OnlyDegradedLinks() {
			r.warnf("%s did not load, so those refs answer nothing while every other ref is "+
				"served: %s. Restore what each names, fix its selector, or take the entry out "+
				"with `sudo faramir link rm REF`, then `sudo systemctl restart faramir-broker`: "+
				"the broker fingerprints a linked file by mtime and size, so a repair that "+
				"changes neither leaves its view as it was",
				brokercheck.LinkEntries(len(report.Secrets.DegradedLinks)), report.DegradedRefs())
			r.step("validate", false, "installed; linked refs to fix")
			return nil
		}
		// Refs the redactor refused. Reported and carried on from, like the links
		// above and for the same reason: what is wrong is one value rather than
		// the install, and the run has already written the config.
		//
		// This command rewrites config.toml before it validates, and [secret]
		// min_length is one of the settings it writes. Failing here would make the
		// bound impossible to raise: `--secret-min-length 12` on a host holding a
		// shorter value would record the new bound and then fail over the values it
		// just refused, leaving a run that wrote the config and reported failure.
		// An install cannot lengthen a secret either. `faramir doctor` fails on
		// this and `faramir status` exits non-zero over it, so a host in this state
		// is not one anything calls healthy.
		if report.OnlyNotRedactable() {
			r.warnf("%d ref(s) cannot be redacted, so they are never injected: %s. Fix each with "+
				"`sudo faramir vault edit`; the reason beside it says how",
				len(report.Secrets.NotRedactable), report.RefusedRefs())
			r.step("validate", false, "installed; refs to fix")
			return nil
		}
		return fmt.Errorf("the installed config does not work for %s: %w\nA [secret] file named there is one "+
			"the broker could not load. A ref under not_redactable needs fixing instead, and a "+
			"[[secret.link]] entry there claims a ref the managed store defines: remove it "+
			"with `sudo faramir link rm REF`",
			r.layout.BrokerUser, checkErr)
	}

	// A value absent from the set is neither injectable nor redacted, so zero refs
	// from a secrets directory that exists is a broker protecting nothing while
	// looking healthy. Guarded on the resolved files rather than the patterns, no
	// files at all being what a first install looks like.
	if len(report.Secrets.Files) > 0 && report.Secrets.Count == 0 {
		r.warnf("the broker read %s and loaded no refs, so nothing is injectable "+
			"and nothing is redacted: a command that prints a credential prints it "+
			"in plaintext. %s",
			strings.Join(report.Secrets.Files, ", "), brokercheck.LoadErrorDetail(report.Secrets.Errors))
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
	// Skipped while the broker is refusing, which a managed file that did not
	// load is: this probe would report that refusal as an SSH fault.
	if r.sshKey != "" && !report.Serves() {
		r.warnf("a managed file did not load, so the broker refuses brokered " +
			"commands and what its ssh-agent holds could not be asked. Fix what the " +
			"store reported, then: faramir doctor")
		r.step("broker ssh agent", false, "not asked")
	}
	if r.sshKey != "" && report.Serves() {
		// -C /, so the probe asks about the agent rather than about where init was
		// run from: a brokered command runs in its caller's directory, and one the
		// daemon cannot see fails the probe rather than answering it.
		out, agentErr := runcmd.Output(filepath.Join(r.layout.BinDir, "faramir"),
			"run", "-C", "/", "--quiet", "--", "ssh-add", "-l")
		// The error carries stderr, where the reason is; dropping it reports every
		// failure as "holds no usable key ()".
		if agentErr != nil {
			if why := protocol.NestedRun(); why != "" {
				return fmt.Errorf("could not ask the broker what its agent holds: %s",
					why)
			}
			return fmt.Errorf("could not ask the broker what its agent holds: %w",
				agentErr)
		}
		if !strings.Contains(out, "SHA256") {
			return fmt.Errorf("the broker's ssh-agent holds no usable key (%s), though [ssh] key names %s: "+
				"brokered commands reach no managed host. Check %s can read it and it is not "+
				"passphrase-protected, then restart faramir-broker",
				strings.TrimSpace(out), r.sshKey, r.layout.BrokerUser)
		}
		r.step("broker ssh agent", false, "holds a usable key")
	}

	return nil
}
