package doctor

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// No config is not a config out of reach. Reported n/a rather than failed, or
// a host that has not been installed yet reads as one that is broken.
func TestTheConfigReachCheckIsNotAFailureWhenThereIsNoConfig(t *testing.T) {
	var report Report
	diagnoseConfigReadable(&report, Options{
		ConfigDir: t.TempDir(), BrokerUser: "faramir-broker",
	})
	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want one", report.Findings)
	}
	if report.Findings[0].Status != StatusNA {
		t.Errorf("status = %v, want n/a for a config that is not there", report.Findings[0].Status)
	}
}

// The finding has to say what an operator does next: which account, which file,
// that the daemons are still running on what they loaded, and that a reload
// will refuse rather than take the change.
func TestTheConfigReachFailureSaysWhatItMeansForAReload(t *testing.T) {
	me, err := user.Current()
	if err != nil || me.Uid == "0" {
		t.Skip("this asserts what a caller who cannot read the config is told")
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte("[command]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	// An account that cannot be named answers no to canRead, which is the same
	// answer the broker gives for a directory it cannot enter.
	var report Report
	diagnoseConfigReadable(&report, Options{
		ConfigDir: dir, BrokerUser: "no-such-account-here",
	})
	if len(report.Findings) != 1 || report.Findings[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want one failure", report.Findings)
	}
	detail := report.Findings[0].Detail
	for _, want := range []string{"no-such-account-here", "config.toml", "reload"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the finding does not mention %q: %s", want, detail)
		}
	}
}
