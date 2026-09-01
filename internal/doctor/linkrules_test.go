package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func TestDoctorPassesWhenALinkedFileIsRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/home/operator/.config/gh/hosts.yml)",
	    "Edit(/home/operator/.config/gh/hosts.yml)"
	  ]}
	}`)
	var report Report
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.config/gh/hosts.yml"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// The state this check exists for: a link in the config whose path the deny
// rules do not name, which is a value in the redactor whose plaintext the agent
// can still open.
func TestDoctorFailsWhenALinkedFileIsNotRefused(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(**/*.key)"]}
	}`)
	var report Report
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{"/home/operator/.npmrc", "faramir init"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("the finding does not name %q: %s", want, finding.Detail)
		}
	}
}

// Nothing to compare against is not a pass. An account with no rule file
// refuses nothing, and reporting OK would say the opposite.
func TestDoctorDoesNotClaimCoverageWithNoRuleFile(t *testing.T) {
	var report Report
	linkedFilesCheck.report(&report, "linked files", t.TempDir(), []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status == StatusOK {
		t.Errorf("an account with no rule file was reported as covered: %s", finding.Detail)
	}
}

func TestDoctorSaysSoWhenNothingIsLinked(t *testing.T) {
	var report Report
	diagnoseLinkedFiles(&report, Options{}, &config.Config{})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// findingFor is the one finding a check reported, or a failure naming what was
// there instead.
func findingFor(t *testing.T, report Report, name string) Finding {
	t.Helper()
	for _, finding := range report.Findings {
		if finding.Name == name {
			return finding
		}
	}
	t.Fatalf("no %q finding in %+v", name, report.Findings)
	return Finding{}
}

// The drift report renders what faramir writes now and reports the difference
// as rules to delete. Without the linked paths in that render, every rule the
// links put there reads as one faramir has stopped writing, and the operator is
// told to remove the rules the check beside it demands.
func TestALinkedPathIsNotReportedAsStaleDrift(t *testing.T) {
	dir := t.TempDir()
	body := "[command]\ntimeout_sec = 600\n\n[[secret.link]]\n" +
		"ref = \"aws/secret\"\npath = \"/home/operator/.aws/credentials\"\n" +
		"type = \"ini\"\nkey = \"default/aws_secret_access_key\"\n"
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	// "credentials" is in protectedPaths, so looksManaged calls this faramir's
	// and the finding would name it.
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/home/operator/.aws/credentials)",
	    "Edit(/home/operator/.aws/credentials)"
	  ]}
	}`)

	var report Report
	reportRuleDrift(&report, home, dir)

	finding := findingFor(t, report, "agent rule drift")
	if strings.Contains(finding.Detail, "/home/operator/.aws/credentials") {
		t.Errorf("a linked path was reported as a rule to remove: %s", finding.Detail)
	}
}

// An allow entry names the path and refuses nothing: coverage read with the
// wide entry set reported a file as refused that a rule explicitly grants.
func TestAnAllowRuleDoesNotCountAsCoverage(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"allow": ["Read(/home/operator/.npmrc)"], "deny": []}
	}`)
	var report Report
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: an allow vouched for a deny: %s",
			finding.Status, finding.Detail)
	}
}

// A rule file that does not parse is not vouched for by its siblings: what it
// refuses is unknown, which is a failure naming the file rather than a silent
// skip that leaves coverage to whatever else is present.
func TestAnUnparseableRuleFileFailsCoverage(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{"permissions": {"deny": [,]}}`)
	var report Report
	linkedFilesCheck.report(&report, "linked files", home, []string{"/home/operator/.npmrc"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
	if !strings.Contains(finding.Detail, ".claude/settings.json") {
		t.Errorf("the failure does not name the broken file: %s", finding.Detail)
	}
}

// Anchored on the left as well as the right: a rule about a longer name must
// not vouch for a shorter one it happens to end with.
func TestARuleAboutALongerNameDoesNotVouchForItsSuffix(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(**/my.env)"]}
	}`)
	var report Report
	linkedFilesCheck.report(&report, "linked files", home, []string{".env"})

	finding := findingFor(t, report, "linked files")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: **/my.env vouched for .env: %s",
			finding.Status, finding.Detail)
	}
}
