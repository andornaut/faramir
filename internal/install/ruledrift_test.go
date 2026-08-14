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
// and an object keyed by pattern.  A key whose value is not a verdict is
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

// An entry about anything faramir does not manage is not reported, which is
// what keeps this from naming every line of somebody's settings.
func TestOnlyRulesAboutManagedPathsAreConsidered(t *testing.T) {
	if looksManaged("Read(**/notes.md)", "/etc/faramir") {
		t.Error("an unrelated rule was treated as faramir's business")
	}
	if looksManaged("Bash(git status)", "/etc/faramir") {
		t.Error("a command rule was treated as faramir's business")
	}
	if !looksManaged("Read(**/id_ed25519)", "/etc/faramir") {
		t.Error("a rule about an SSH private key was not recognised")
	}
	if !looksManaged("*sops/age/*", "/etc/faramir") {
		t.Error("a rule about the age identities was not recognised")
	}
}

// The case this exists for: a spelling the last version wrote, still in place,
// and not in what is written now.
func TestAStaleRuleIsFound(t *testing.T) {
	layout := testLayout()
	current, err := render("agent/claude/settings.json", layout)
	if err != nil {
		t.Fatal(err)
	}
	// One rule faramir used to write, one it still writes, and one that is the
	// operator's own.
	home := writeRules(t, ".claude/settings.json", `{
	  "permissions": {"deny": [
	    "Read(**/*.sops.yml)",
	    "Read(**/retired-secrets.key)",
	    "Read(**/notes.md)"
	  ]}
	}`)

	got, err := staleRules(filepath.Join(home, ".claude/settings.json"), current, "/etc/faramir")
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(got, " ")
	if !strings.Contains(joined, "retired-secrets.key") {
		t.Errorf("the rule faramir no longer writes was not found: %v", got)
	}
	// Still written, so not stale.
	if strings.Contains(joined, ".sops.yml") {
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
	current, err := render("agent/claude/settings.json", layout)
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
	  "permissions": {"deny": ["Read(**/retired-secrets.key)"]}
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
	if !strings.Contains(got.Detail, "retired-secrets.key") {
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
	current, err := render("agent/claude/settings.json", layout)
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

// A rule naming a layout faramir has stopped using is what this check exists to
// find, and the name is the only thing that identifies one.
//
// Nothing records what earlier versions wrote, and nothing should: a stored list
// goes stale the moment somebody edits the file by hand. So the inference has to
// recognise faramir's own name rather than only the directories this build
// happens to use. Matching the compiled-in defaults alone sees an install that
// never moved and nothing else, which is the case least likely to have drifted.
func TestARuleFromAnEarlierLayoutIsRecognised(t *testing.T) {
	const configDir = "/home/op/.config/faramir"
	for _, entry := range []string{
		// The config directory faramir shipped before it moved under ~/.config.
		"Read(/home/op/.faramir/**)",
		"Edit(/home/op/.faramir/secrets/**)",
		"Read(**/.faramir/**)",
		// The compiled-in default, on a host that is no longer using it.
		"Read(/etc/faramir/**)",
		// A --config-dir somebody moved away from.
		"Read(/opt/faramir/**)",
		// And the one this install actually uses.
		"Read(" + configDir + "/**)",
	} {
		if !looksManaged(entry, configDir) {
			t.Errorf("%q names a faramir layout and was not recognised, so a leftover "+
				"from it is never reported", entry)
		}
	}
	// Still narrow in the other direction: an unrelated rule is not this check's
	// business, or every line of somebody's settings ends up in the finding.
	for _, entry := range []string{"Read(**/notes.md)", "Bash(git status)", "Edit(src/**)"} {
		if looksManaged(entry, configDir) {
			t.Errorf("%q is nothing to do with faramir and was reported", entry)
		}
	}
}
