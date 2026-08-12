package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// canRead answers false for an account it cannot name, which is the same answer
// a boundary that holds gives, so a check that asks about an unnamed operator
// and then passes reports a boundary nobody established.
func TestTheSSHKeyCheckDoesNotPassOnAnUnaskedOperator(t *testing.T) {
	key := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(key, []byte("not a key"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{}
	cfg.Ssh.Key = key

	var unnamed DoctorReport
	diagnoseSSHKey(&unnamed, DoctorOptions{ExecUser: "ex"}, cfg)
	finding := only(t, unnamed)
	if finding.Status != StatusWarn {
		t.Errorf("status %q, want %q: %s", finding.Status, StatusWarn, finding.Detail)
	}
	if unnamed.NotAsked != 1 {
		t.Errorf("counted %d unasked, want 1: a probe nobody could put is one the "+
			"footer has to report", unnamed.NotAsked)
	}

	// Named, the same host is a pass: the skip is about the question, not the key.
	var named DoctorReport
	diagnoseSSHKey(&named, DoctorOptions{ExecUser: "ex", OperatorUser: "op"}, cfg)
	if got := only(t, named); got.Status != StatusOK {
		t.Errorf("status %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	if named.NotAsked != 0 {
		t.Errorf("counted %d unasked with the operator named, want 0", named.NotAsked)
	}
}

// The same for the account that would be choosing its own answer: an operator
// that can write the helper decides every approval on the host.
func TestTheSudoArrangementDoesNotPassOnAnUnaskedOperator(t *testing.T) {
	dir := t.TempDir()
	original := pamDir
	pamDir = dir
	t.Cleanup(func() { pamDir = original })

	helper := filepath.Join(dir, "faramir-approve")
	cfg := &config.Config{}
	cfg.Sudo.ExecUser = "ex"
	cfg.Sudo.PamService = "faramir-sudo"
	cfg.Sudo.Helper = helper
	if err := os.WriteFile(filepath.Join(dir, cfg.Sudo.PamService),
		[]byte("auth requisite pam_exec.so seteuid quiet "+helper+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	var unnamed DoctorReport
	diagnoseSudoArrangement(&unnamed, DoctorOptions{ExecUser: "ex"}, cfg)
	finding := only(t, unnamed)
	if finding.Status != StatusWarn {
		t.Errorf("status %q, want %q: %s", finding.Status, StatusWarn, finding.Detail)
	}
	if unnamed.NotAsked != 1 {
		t.Errorf("counted %d unasked, want 1", unnamed.NotAsked)
	}

	var named DoctorReport
	diagnoseSudoArrangement(&named, DoctorOptions{ExecUser: "ex", OperatorUser: "op"}, cfg)
	if got := only(t, named); got.Status != StatusOK {
		t.Errorf("status %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	if named.NotAsked != 0 {
		t.Errorf("counted %d unasked with the operator named, want 0", named.NotAsked)
	}
}

// One warn line stands for both groups, so the count has to be both: a host with
// a secrets group of its own has two checks behind that line.
func TestTheGroupBailOutCountsEveryGroupItSkipped(t *testing.T) {
	var shared DoctorReport
	diagnoseGroup(&shared, DoctorOptions{ClientGroup: "dev", SecretsGroup: "dev"})
	if shared.NotAsked != 1 {
		t.Errorf("counted %d unasked with one group, want 1", shared.NotAsked)
	}

	var split DoctorReport
	diagnoseGroup(&split, DoctorOptions{ClientGroup: "dev", SecretsGroup: "faramir-keeper"})
	if split.NotAsked != 2 {
		t.Errorf("counted %d unasked with a secrets group of its own, want 2: the "+
			"early return skips that check too", split.NotAsked)
	}
}

// Whether a rule exists and covers the log this config names is read from a
// path and a $PATH, so it is not behind the root gate: an unbounded audit log
// ends in every brokered command being refused, and a caller without root has
// to hear about it.  The two questions that do need root -- whether logrotate
// has applied the rule, and how large the log has grown -- are reported as
// unasked, which still names the log rather than standing in for it.
func TestLogRotationIsReportedWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("this asserts what a caller without root is told")
	}
	dir := t.TempDir()
	original := systemUnitDir
	systemUnitDir = dir
	t.Cleanup(func() { systemUnitDir = original })
	for unit, account := range map[string]string{
		"faramir-broker.service": "faramir-broker",
		"faramir-keeper.service": "faramir-keeper",
		"faramir-exec.service":   "faramir-exec",
	} {
		if err := os.WriteFile(filepath.Join(dir, unit),
			[]byte("[Service]\nUser="+account+"\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	configDir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(configDir, "secrets"), 0o750); err != nil {
		t.Fatal(err)
	}
	logPath := filepath.Join(dir, "audit.log")
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(
		"[server]\nallowed_group = \"dev\"\n\n[audit]\nlog_path = \""+
			logPath+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	found := findingsNamed(Diagnose(DoctorOptions{ConfigDir: configDir}), "log rotation")
	if len(found) == 0 {
		t.Fatal("no log rotation finding in a run without root")
	}
	// Whatever the verdict, it is about the log this config names rather than a
	// line saying the question went unput.
	if !strings.Contains(found[0].Detail, logPath) {
		t.Errorf("finding is %q %q, want it to name %s",
			found[0].Status, found[0].Detail, logPath)
	}
}

// A warn either says a question could not be put, and is counted under the
// totals, or it is a finding about this host and is not.  Nothing but the call
// it goes through decides which, so this is what keeps them paired: a check that
// says it did not ask, and does not count itself, reports a host as examined
// that was not.
func TestEveryWarnThatSaysItDidNotAskCountsItself(t *testing.T) {
	// The phrasings a check uses when the question was not put.  Read from the
	// findings rather than listed per check, so a new one is covered the day it
	// is written.
	didNotAsk := []string{"not asked", "was not checked", "went unchecked",
		"is not known", "were not made", "was not asked", "went unasked"}
	for _, probe := range []struct {
		name string
		run  func(*DoctorReport)
	}{
		{"no systemd", func(r *DoctorReport) {
			original := systemdRunning
			systemdRunning = func() bool { return false }
			defer func() { systemdRunning = original }()
			diagnoseUnits(r, DoctorOptions{})
		}},
		{"no broker", func(r *DoctorReport) { diagnoseVersion(r, DoctorOptions{}) }},
		{"no operator", func(r *DoctorReport) { diagnoseOperatorKeys(r, DoctorOptions{}) }},
		{"no root", func(r *DoctorReport) {
			if os.Geteuid() == 0 {
				return // the branch under test is the one a caller without root takes
			}
			diagnoseBoundaries(r, DoctorOptions{}, &config.Config{}, servesUnknown)
		}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			var report DoctorReport
			probe.run(&report)
			for _, finding := range report.Findings {
				if finding.Status != StatusWarn {
					continue
				}
				said := false
				for _, phrase := range didNotAsk {
					if strings.Contains(finding.Detail, phrase) {
						said = true
					}
				}
				if said && report.NotAsked == 0 {
					t.Errorf("%q says the question was not put and nothing was counted: %s",
						finding.Name, finding.Detail)
				}
			}
		})
	}
}

// And the pairing is structural: NotAsked moves only through unasked(), so a
// warn added any other way cannot quietly claim a check was skipped.
func TestUnaskedCountsAndWarnsTogether(t *testing.T) {
	var report DoctorReport
	report.unasked("probe", 3, "three checks stood behind this line")
	if report.NotAsked != 3 {
		t.Errorf("NotAsked = %d, want 3", report.NotAsked)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
		t.Errorf("want one warn finding, got %+v", report.Findings)
	}
	report.add("finding", StatusWarn, "something this host has")
	if report.NotAsked != 3 {
		t.Errorf("a plain warn changed the unasked count: %d", report.NotAsked)
	}
}
