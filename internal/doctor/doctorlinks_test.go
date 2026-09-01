package doctor

import (
	"os"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func TestDoctorLinkedAccessSaysSoWhenNothingIsLinked(t *testing.T) {
	var report Report
	diagnoseLinkedAccess(&report, Options{}, &config.Config{})

	finding := findingFor(t, report, "linked file access")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// canRead answers false for an account it cannot name, which is what it
// answers for one that is properly shut out, so an unnamed account is not a
// pass and not a failure.
func TestDoctorLinkedAccessIsUnaskedWithoutBothAccounts(t *testing.T) {
	cfg := &config.Config{}
	cfg.Secret.Links = []config.Link{{Ref: "gh/token", Path: "/nowhere"}}
	var report Report
	diagnoseLinkedAccess(&report, Options{BrokerUser: "faramir-broker"}, cfg)

	finding := findingFor(t, report, "linked file access")
	if finding.Status == StatusOK || finding.Status == StatusFailed {
		t.Errorf("status = %v, want neither a pass nor a verdict: %s",
			finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, "not asked") {
		t.Errorf("the finding does not say the question went unasked: %s", finding.Detail)
	}
}

// An unprivileged doctor cannot become the broker or the executor, so whether a
// linked file is readable cannot be asked: runuser fails for every path, and
// reading that failure as the answer reported the broker unable to open files
// it was serving values from. Unasked, not a verdict. The suite runs without
// root, which is exactly the condition under test.
func TestLinkedAccessIsUnaskedWithoutRoot(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, where the question can be asked for real")
	}
	var report Report
	cfg := &config.Config{}
	cfg.Secret.Links = []config.Link{{Ref: "gh/token", Path: "/tmp/nope", Type: "text"}}
	diagnoseLinkedAccess(&report, Options{
		BrokerUser: "faramir-broker", ExecUser: "faramir-exec"}, cfg)

	finding := findingFor(t, report, "linked file access")
	if finding.Status == StatusOK || finding.Status == StatusFailed {
		t.Errorf("status = %v, want neither a pass nor a verdict: %s",
			finding.Status, finding.Detail)
	}
	if report.NotAsked == 0 {
		t.Error("nothing was recorded as unasked")
	}
}
