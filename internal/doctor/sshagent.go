package doctor

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/termsafe"
)

// sshAgentRefused is reported both before the probe runs and after the broker
// refuses it.
const sshAgentRefused = "not asked: a managed file did not load, so the broker " +
	"refuses the brokered command this probe runs"

// sshAgentUnanswered is the other reason the probe cannot be put: a broker that
// answered nothing when the install was looked up answers a brokered command no
// better.
const sshAgentUnanswered = "not asked: the broker did not answer, so the " +
	"brokered command this probe runs cannot be sent"

// diagnoseSSHAgent asks what a brokered command would actually get, rather than
// reading the key off disk, and asks as the operator: root is not in the client
// group the broker checks against.
//
// Skipped when no key is configured: SSH is then arranged for the executor's
// uid some other way, and `ssh-add -l` exits non-zero for want of an agent,
// which is not a fault. Not skipped for want of root.
func diagnoseSSHAgent(report *Report, opts Options, cfg *config.Config, serves brokerServes) {
	if cfg == nil {
		report.unaskedf("ssh agent", 1, "the config did not load, so which key the "+
			"broker lends is unknown")
		return
	}
	// An install always writes one: `init` mints a key whether or not the host
	// turns out to need it, and renders the path into [ssh] key, so an empty one
	// is an edit rather than a host that authenticates some other way. Reported
	// as a fault because nothing else would say so: the broker comes up, every
	// other check passes, and a brokered command reaching a managed host fails
	// with ssh's own error at the point of use.
	if cfg.Ssh.Key == "" {
		where := cfg.Path
		if where == "" {
			where = "the config"
		}
		report.addf("ssh agent", StatusFailed, "no [ssh] key is configured, so "+
			"the broker lends no identity and a brokered command that reaches a managed "+
			"host fails with ssh's own error. `faramir init` writes one on every run, so "+
			"this is an edit to %s. Re-run `sudo faramir init`, with --ssh-key to name a "+
			"key of your own", where)
		return
	}
	if reason := skipSSHProbe(serves, opts.BrokerVersion); reason != "" {
		report.unaskedf("ssh agent", 1, "%s", reason)
		return
	}
	// The probe stands for the agent account's reach, so it must run as that
	// account. Root gets there through runuser; the agent running doctor is
	// already it; anybody else's answer would be reported as the operator's.
	if os.Geteuid() != 0 {
		if current, err := user.Current(); err != nil || current.Username != opts.AgentUser {
			report.unaskedf("ssh agent", 1, "the probe has to run as %s. Run "+
				"doctor as that account, or as root", opts.AgentUser)
			return
		}
	}
	// -C /, so the probe asks about the agent rather than about where doctor was
	// run from. A brokered command runs in its caller's directory, and every
	// faramir unit has PrivateTmp=true, so a caller standing anywhere the daemon
	// cannot see, a host-created directory under /tmp among them, gets
	// `bad_request: cwd does not exist for this daemon` and this check reports a
	// working agent as failed. Root is a directory every account can enter.
	out, err := asOperator(opts, filepath.Join(hostlayout.DefaultBinDir, "faramir"),
		"run", "-C", "/", "--quiet", "--", "ssh-add", "-l")
	reportSSHProbe(report, cfg, serves, out, err)
}

// skipSSHProbe reports why the probe cannot be put, empty when it can. The
// probe sends a brokered command, so a broker that refuses one or answers
// nothing leaves no answer to be had, and reporting either as the agent's own
// would fail a host whose agent is fine. The established refusal comes first:
// it names the fault to fix.
func skipSSHProbe(serves brokerServes, brokerVersion string) string {
	switch {
	case serves == servesNothing:
		return sshAgentRefused
	case brokerVersion == "":
		return sshAgentUnanswered
	}
	return ""
}

// reportSSHProbe turns the probe's answer into a finding. A refusal from a
// broker --check found holding values is neither the agent's answer nor a skip:
// --check reads the managed files itself, so a daemon refusing what those files
// cover came up before they were written.
func reportSSHProbe(report *Report, cfg *config.Config, serves brokerServes, out string, err error) {
	switch classifySSHProbe(out, err) {
	case sshProbeHasKey:
		report.addf("ssh agent", StatusOK, "holds a usable key")
	case sshProbeRefused:
		if serves == servesValues {
			report.addf("ssh agent", StatusFailed, "the broker refuses brokered "+
				"commands even though --check read every managed file as the broker: the "+
				"running daemon started before the values were there and has not read them "+
				"since. Restart faramir-broker")
			return
		}
		report.unaskedf("ssh agent", 1, "%s", sshAgentRefused)
	case sshProbeEmpty:
		report.addf("ssh agent", StatusFailed, "the agent holds nothing, though [ssh] "+
			"key names %s, so every brokered command that reaches a managed host "+
			"fails to authenticate. Place the key and restart faramir-broker",
			cfg.Ssh.Key)
	case sshProbeUnreachable:
		// Bounded: out is a brokered command's whole output, and a finding is a
		// line an operator reads, not the record.
		report.addf("ssh agent", StatusFailed, "could not ask the broker: %v: %s",
			err, termsafe.Bound(strings.TrimSpace(out), 512))
	}
}

// sshProbeResult is what `ssh-add -l` through the broker came back as.
type sshProbeResult int

const (
	sshProbeHasKey sshProbeResult = iota
	sshProbeRefused
	sshProbeEmpty
	sshProbeUnreachable
)

// classifySSHProbe reads the probe's answer. Success first: ssh-add exits
// non-zero both when the agent is empty and when it could not be reached, so
// err alone does not say which and the output decides. The refusal is the
// broker declining to run the probe at all.
func classifySSHProbe(out string, err error) sshProbeResult {
	switch {
	case strings.Contains(out, "SHA256"):
		return sshProbeHasKey
	case err != nil && strings.Contains(err.Error(), refusedCode):
		return sshProbeRefused
	case strings.Contains(out, "no identities"):
		return sshProbeEmpty
	}
	return sshProbeUnreachable
}
