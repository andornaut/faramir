package agentcfg

// Reading a rule file back.

import (
	"testing"
)

// The shapes both kinds of rule file use, read the same way: a list of strings
// and an object keyed by pattern. A key whose value is not a verdict is
// configuration rather than a rule, and stays out.
func TestRuleEntriesReadsBothShapes(t *testing.T) {
	got, err := RuleEntries([]byte(`{
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

// A rule naming a longer path must not vouch for a shorter one: with both
// ~/.npmrc and ~/.npmrc-work linked, a rule covering only the second would
// otherwise report the first as refused while the agent can still read it.
func TestALongerPathDoesNotCoverAShorterOne(t *testing.T) {
	entries := map[string]bool{"Read(/home/operator/.npmrc-work)": true}
	if Named(entries, "/home/operator/.npmrc") {
		t.Error("a longer sibling was accepted as covering the shorter path")
	}
	if !Named(entries, "/home/operator/.npmrc-work") {
		t.Error("the path the rule actually names was not matched")
	}
	// Each agent wraps a path its own way, and all of those still match. The
	// two-slash form is what claudeRules renders: without it every declared path
	// reports as refused by nothing, the rule that refuses it being right there.
	for _, entry := range []string{
		"Read(//home/operator/.npmrc)", "Edit(//home/operator/.npmrc)",
		"Read(/home/operator/.npmrc)", "Edit(/home/operator/.npmrc)",
		"/home/operator/.npmrc",
	} {
		if !Named(map[string]bool{entry: true}, "/home/operator/.npmrc") {
			t.Errorf("%q was not read as naming the path", entry)
		}
	}
	// And the anchor does not widen what a rule vouches for.
	if Named(map[string]bool{"Read(//home/operator/.npmrc-work)": true},
		"/home/operator/.npmrc") {
		t.Error("a root-anchored longer sibling was accepted as covering the shorter path")
	}
	// A directory rule reaches the directory itself in that spelling too.
	if !Named(map[string]bool{"Read(//home/operator/.ssh/**)": true},
		"/home/operator/.ssh") {
		t.Error("a root-anchored subtree rule did not vouch for its own directory")
	}
}
