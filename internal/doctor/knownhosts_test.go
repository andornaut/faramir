package doctor

import (
	"os"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The executor's file is inside a 0700 home, so without root the answer is
// unknown rather than none, and it counts against what doctor did not ask.
func TestDiagnoseKnownHostsDoesNotGuessWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads the executor's home, so the check is answered rather than skipped")
	}
	var report Report
	cfg := &config.Config{}
	cfg.Ssh.Key = "/etc/faramir/id_ed25519"

	diagnoseKnownHosts(&report, Options{ExecUser: "faramir-exec"}, cfg)

	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1: an unanswered check is not a passing one", report.NotAsked)
	}
	if len(report.Findings) != 1 || report.Findings[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", report.Findings)
	}
	if !strings.Contains(report.Findings[0].Detail, "/var/lib/faramir-exec/.ssh/known_hosts") {
		t.Errorf("does not name the file it could not read: %s", report.Findings[0].Detail)
	}
}

// A host that authenticates some other way has no key and no host keys to hold,
// so nothing is reported: doctor answers for what was installed.
func TestDiagnoseKnownHostsSaysNothingWithoutAKey(t *testing.T) {
	var report Report

	diagnoseKnownHosts(&report, Options{ExecUser: "faramir-exec"}, &config.Config{})

	if len(report.Findings) != 0 {
		t.Errorf("reported %+v for a host with no [ssh] key", report.Findings)
	}
}
