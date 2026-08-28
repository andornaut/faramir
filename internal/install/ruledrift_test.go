package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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

// The shapes both kinds of rule file use, read the same way: a list of strings
// and an object keyed by pattern. A key whose value is not a verdict is
// configuration rather than a rule, and stays out.
func TestRuleEntriesReadsBothShapes(t *testing.T) {
	got, err := ruleEntries([]byte(`{
	  "permissions": {"deny": ["Read(**/*.key)", "Edit(**/*.key)"]},
	  "permission": {"read": {"*id_rsa": "deny", "*.md": "allow"}},
	  "model": "something"
	}`))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Read(**/*.key)", "Edit(**/*.key)", "*id_rsa", "*.md"} {
		if !got[want] {
			t.Errorf("%q was not read as a rule", want)
		}
	}
	// The keys above the rules are not rules.
	for _, unwanted := range []string{"permissions", "deny", "read", "model", "something"} {
		if got[unwanted] {
			t.Errorf("%q was read as a rule", unwanted)
		}
	}
}

// The case this exists for: a spelling the last version wrote, still in place,
// and not in what is written now.
func TestAStaleRuleIsFound(t *testing.T) {
	layout := testLayout()
	current, err := renderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	// One rule faramir no longer writes, one it still writes, and one that is the
	// operator's own. The stale one names a config directory this install moved
	// away from, which is what a --config-dir run leaves behind.
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(/opt/conf/**)",
	    "Read(/opt/retired-faramir/**)",
	    "Read(**/notes.md)"
	  ]}
	}`)

	got, err := staleRules(filepath.Join(home, ".claude/settings.json"), current, "/etc/faramir")
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
	layout := testLayout()
	current, err := renderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	path := filepath.Join(home, "settings.json")
	if err := os.WriteFile(path, current, 0o600); err != nil {
		t.Fatal(err)
	}

	got, err := staleRules(path, current, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Errorf("a file holding exactly what faramir writes reported %v", got)
	}
}

// The finding says what it cannot know: an operator's own rule about a managed
// path is indistinguishable from one of faramir's left behind, so it has to
// name that rather than instruct a deletion.
func TestTheDriftFindingSaysItCannotTellWhoseRuleItIs(t *testing.T) {
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": ["Read(/opt/retired-faramir/**)"]}
	}`)

	var report DoctorReport
	reportRuleDrift(&report, home, testLayout().ConfigDir)

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
	layout := testLayout()
	current, err := renderAccount("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	home := writeRules(t, ".claude/settings.json", string(current))

	var report DoctorReport
	reportRuleDrift(&report, home, layout.ConfigDir)

	if len(report.Findings) != 1 || report.Findings[0].Status != StatusOK {
		t.Fatalf("findings = %+v, want one ok row", report.Findings)
	}
	if report.Failed || report.NotAsked != 0 {
		t.Errorf("a clean home was not reported as clean: %+v", report)
	}
}

// What the drift check is willing to have an opinion about. It has to cover a
// layout faramir has stopped using, the name being the only thing that
// identifies one: nothing records what earlier versions wrote, and nothing
// should, a stored list going stale the moment somebody edits the file by hand.
// Matching the compiled-in defaults alone sees an install that never moved and
// nothing else, which is the case least likely to have drifted.
//
// And it has to stay narrow in the other direction, or every line of somebody's
// settings ends up in the finding.
func TestLooksManagedMatchesOnlyTheInstallersOwnLine(t *testing.T) {
	const configDir = "/home/op/.config/faramir"
	for _, tc := range []struct {
		entry string
		want  bool
	}{
		// The config directory faramir shipped before it moved under ~/.config.
		{"Read(/home/op/.faramir/**)", true},
		{"Edit(/home/op/.faramir/secrets/**)", true},
		{"Read(**/.faramir/**)", true},
		// The compiled-in default, on a host that is no longer using it.
		{"Read(/etc/faramir/**)", true},
		// A --config-dir somebody moved away from.
		{"Read(/opt/faramir/**)", true},
		// And the one this install actually uses.
		{"Read(" + configDir + "/**)", true},
		// A credential of the operator's own, and an age identity they keep
		// themselves. faramir writes a rule for neither, so a rule naming one is
		// theirs and is never reported as drift.
		{"Read(**/id_ed25519)", false},
		{"Read(**/*.pem)", false},
		{"Read(**/age.key)", false},

		{"Read(**/notes.md)", false},
		{"Bash(git status)", false},
		{"Edit(src/**)", false},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			if got := looksManaged(tc.entry, configDir); got != tc.want {
				t.Errorf("looksManaged = %v, want %v", got, tc.want)
			}
		})
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
	dir := configDirWith(t, "[server]\nagent_user = \""+agent+"\"\n")
	if got := ruleLayout(dir).AgentUser; got != agent {
		t.Errorf("ruleLayout carries AgentUser %q, want %q: doctor would re-render "+
			"without the home spellings and call the installed file drifted", got, agent)
	}
	// And a config that names none leaves it empty rather than guessing, which
	// is what installDirs and the rendering both skip.
	bare := configDirWith(t, "[command]\ntimeout_sec = 600\n")
	if got := ruleLayout(bare).AgentUser; got != "" {
		t.Errorf("ruleLayout invented an agent user %q from a config naming none", got)
	}
}
