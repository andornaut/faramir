package doctor

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/layouttest"
)

// installRulesWithOmission is the check as diagnoseInstallRules builds it: the
// renderer's own predicate, so the test and the install agree about which path
// carries no rule.
func installRulesWithOmission() coverageCheck {
	layout := layouttest.Layout()
	check := installRulesCheck
	check.omitted = func(agent, path string) bool {
		return agentcfg.OmittedFrom(agent, layout, path)
	}
	return check
}

// The gap the renderer leaves is not drift, so a file without the rule passes.
// Asserted beside the failure below: a check that reported both ways would be
// one no install could satisfy.
func TestNoRuleForTheWrapperDirectoryIsNotReported(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(//opt/conf)"]}
	}`)
	var report Report
	installRulesWithOmission().report(&report, "install rules", home,
		[]string{layouttest.Layout().LibexecDir})

	finding := findingFor(t, report, "install rules")
	if finding.Status != StatusOK {
		t.Errorf("status = %v, want OK: %s", finding.Status, finding.Detail)
	}
}

// A rule for the path the renderer omits, which is what an older install left
// and what a run against a new --config-dir cannot take out, its record of what
// it wrote naming nothing. Claude Code checks a Bash command's paths against
// this before it acts on the hook's decision, so the rule refuses the wrapper
// invocation every command is rewritten into and the agent runs nothing in an
// enrolled tree. Until this check existed the host reported ok.
func TestARuleForTheWrapperDirectoryFails(t *testing.T) {
	layout := layouttest.Layout()
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(//`+strings.TrimPrefix(layout.LibexecDir, "/")+`)"]}
	}`)
	var report Report
	installRulesWithOmission().report(&report, "install rules", home,
		[]string{layout.LibexecDir})

	finding := findingFor(t, report, "install rules")
	if finding.Status != StatusFailed {
		t.Fatalf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
	for _, want := range []string{layout.LibexecDir, "~/.claude/settings.json", "Remove it"} {
		if !strings.Contains(finding.Detail, want) {
			t.Errorf("the finding does not say %q: %s", want, finding.Detail)
		}
	}
}

// The omission is Claude Code's alone, so every other agent's file is still
// expected to carry the rule and is reported when it does not.
func TestAnotherAgentIsStillShortOfTheWrapperDirectory(t *testing.T) {
	layout := layouttest.Layout()
	home := writeRules(t, ".gemini/antigravity-cli/settings.json", `{
	  "permissions": {"deny": ["Read(//opt/conf)"]}
	}`)
	var report Report
	installRulesWithOmission().report(&report, "install rules", home,
		[]string{layout.LibexecDir})

	finding := findingFor(t, report, "install rules")
	if finding.Status != StatusFailed {
		t.Errorf("status = %v, want Failed: %s", finding.Status, finding.Detail)
	}
}
