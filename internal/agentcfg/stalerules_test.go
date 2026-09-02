package agentcfg

// Rules an earlier version wrote and this one no longer does.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/layouttest"
)

// The case this exists for: a spelling the last version wrote, still in place,
// and not in what is written now.
func TestAStaleRuleIsFound(t *testing.T) {
	layout := layouttest.Layout()
	current, err := RenderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	// One rule faramir no longer writes, one it still writes, and one that is the
	// operator's own. The stale one names a config directory this install moved
	// away from, which is what a --config-dir run leaves behind.
	path := filepath.Join(t.TempDir(), "settings.json")
	if err := os.WriteFile(path, []byte(`{
	  "permissions": {"deny": [
	    "Read(/opt/conf/**)",
	    "Read(/opt/retired-faramir/**)",
	    "Read(**/notes.md)"
	  ]}
	}`), 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := StaleRules(path, current, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "retired-faramir") {
		t.Errorf("the rule faramir no longer writes was not found: %v", got)
	}
	// Still written, so not stale.
	if strings.Contains(joined, "/opt/conf/**") {
		t.Errorf("a rule faramir still writes was reported as stale: %v", got)
	}
	// Nothing to do with faramir, so never named: reporting an operator's own
	// unrelated rules is how a check gets ignored.
	if strings.Contains(joined, "notes.md") {
		t.Errorf("an unrelated rule was reported: %v", got)
	}
}

// A file holding exactly what faramir writes has nothing stale in it, which is
// the state every host is in the run after an install.
func TestAFreshlyWrittenFileHasNoStaleRules(t *testing.T) {
	layout := layouttest.Layout()
	current, err := RenderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	path := filepath.Join(home, "settings.json")
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := StaleRules(path, current, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a file holding exactly what faramir writes reported %v", got)
	}
}

// doctor re-renders the rules and compares them against the installed file, so
// the layout it renders from has to be the one init rendered. The agent's
// account is part of that: a path under its home is written in the spellings a
// shell expands to it, so a re-render that does not know the home produces
// fewer rules than the host carries and reports the difference as drift on a
// host where nothing is wrong.
func TestTheReRenderKnowsTheAgentsAccount(t *testing.T) {
	const agent = "someoperator"
	dir := layouttest.ConfigDir(t, "[server]\nagent_user = \""+agent+"\"\n")
	if got := RuleLayout(dir).AgentUser; got != agent {
		t.Errorf("RuleLayout carries AgentUser %q, want %q: doctor would re-render "+
			"without the home spellings and call the installed file drifted", got, agent)
	}
	// And a config that names none leaves it empty rather than guessing, which
	// is what agentHome skips.
	bare := layouttest.ConfigDir(t, "[command]\ntimeout_sec = 600\n")
	if got := RuleLayout(bare).AgentUser; got != "" {
		t.Errorf("RuleLayout invented an agent user %q from a config naming none", got)
	}
}
