package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// find is the first finding under a name, or nil.
func find(report DoctorReport, name string) *Finding {
	for i, finding := range report.Findings {
		if finding.Name == name {
			return &report.Findings[i]
		}
	}
	return nil
}

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

// The log-rotation check reads a path, a $PATH and a size and asks no account
// anything, so it is not behind the root gate: an unbounded audit log ends in
// every brokered command being refused, and a caller without root has to hear
// about it.
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
	if err := os.WriteFile(filepath.Join(configDir, "config.toml"), []byte(
		"[server]\nallowed_group = \"dev\"\n\n[audit]\nlog_path = \""+
			filepath.Join(dir, "audit.log")+"\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	logPath := filepath.Join(dir, "audit.log")
	report := Diagnose(DoctorOptions{ConfigDir: configDir})
	finding := find(report, "log rotation")
	if finding == nil {
		t.Fatalf("no log rotation finding in a run without root: %+v", report.Findings)
	}
	// Whatever the verdict, it is about the log this config names rather than a
	// line saying the question went unput.
	if !strings.Contains(finding.Detail, logPath) {
		t.Errorf("finding is %q %q, want it to name %s",
			finding.Status, finding.Detail, logPath)
	}
}
