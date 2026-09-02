package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/layouttest"
)

// writeRules puts a settings file in a home and returns the home.
func writeRules(t *testing.T, rel, body string) string {
	t.Helper()
	home := t.TempDir()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return home
}

// The finding says what it cannot know: an operator's own rule about a managed
// path is indistinguishable from one of faramir's left behind, so it has to
// name that rather than instruct a deletion.
func TestTheDriftFindingSaysItCannotTellWhoseRuleItIs(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(/opt/retired-faramir/**)"]}
	}`)

	var report Report
	reportRuleDrift(&report, home, layouttest.Layout().ConfigDir)

	if len(report.Findings) != 1 {
		t.Fatalf("findings = %+v, want exactly one", report.Findings)
	}
	got := report.Findings[0]
	if got.Status != StatusWarn {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusWarn, got.Detail)
	}
	// Extra refusals, so untidy rather than unguarded.
	if report.Failed {
		t.Error("untidy rules failed the report")
	}
	if !strings.Contains(got.Detail, "retired-faramir") {
		t.Errorf("the finding does not name the rule: %s", got.Detail)
	}
	for _, want := range []string{"not yours", "no longer writes"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the finding does not say %q: %s", want, got.Detail)
		}
	}
}

// A home whose rule files hold exactly what faramir writes reports so, rather
// than the check vanishing: one that only speaks up when something is wrong is
// indistinguishable from one nobody wrote.
func TestTheDriftFindingReportsACleanHome(t *testing.T) {
	layout := layouttest.Layout()
	current, err := agentcfg.RenderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	home := writeRules(t, ".claude/settings.json", string(current))

	var report Report
	reportRuleDrift(&report, home, layout.ConfigDir)

	if len(report.Findings) != 1 || report.Findings[0].Status != StatusOK {
		t.Fatalf("findings = %+v, want one ok row", report.Findings)
	}
	if report.Failed || report.NotAsked != 0 {
		t.Errorf("a clean home was not reported as clean: %+v", report)
	}
}
