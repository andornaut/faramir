package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// denyList is the deny entries of a merged claude settings file, which is where
// the rules an entry renders to end up.
func denyList(t *testing.T, merged []byte) []string {
	t.Helper()
	var parsed struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(merged, &parsed); err != nil {
		t.Fatalf("merged file does not parse: %v\n%s", err, merged)
	}
	return parsed.Permissions.Deny
}

func settings(rules ...string) []byte {
	quoted := make([]string, 0, len(rules))
	for _, rule := range rules {
		quoted = append(quoted, `"`+rule+`"`)
	}
	return []byte(`{"permissions":{"deny":[` + strings.Join(quoted, ",") + `]}}`)
}

// A rule faramir wrote for an entry that has since been removed comes out on
// the next render. Left in, it refuses something nothing declares, and nothing
// in the file says who put it there.
func TestAMergeRemovesARuleNoEntryBacksAnyMore(t *testing.T) {
	// What the last run wrote, and what this one renders: the second entry is
	// gone from the config.
	wrote := []string{`Read(**/secrets*)`, `Read(/etc/faramir/secrets/**)`}
	ours := settings(`Read(/etc/faramir/secrets/**)`)
	existing := settings(`Read(**/secrets*)`, `Read(/etc/faramir/secrets/**)`, `Read(**/mine)`)

	merged, err := mergeJSON(existing, ours, wrote)
	if err != nil {
		t.Fatal(err)
	}
	got := denyList(t, merged)
	if slices.Contains(got, `Read(**/secrets*)`) {
		t.Errorf("the rule for a removed entry is still there: %v", got)
	}
	// The trap: both rules carry the word, and only one of them is stale.
	if !slices.Contains(got, `Read(/etc/faramir/secrets/**)`) {
		t.Errorf("this install's own store was removed: %v", got)
	}
	// Named by no record, so not faramir's to remove however it looks.
	if !slices.Contains(got, `Read(**/mine)`) {
		t.Errorf("a rule faramir never wrote was removed: %v", got)
	}
}

// With no record there is nothing faramir can prove it wrote, so it removes
// nothing: an install from before the record existed, or one whose record was
// lost, merges the way it always did.
func TestAMergeWithNoRecordRemovesNothing(t *testing.T) {
	existing := settings(`Read(**/secrets*)`, `Read(**/mine)`)
	merged, err := mergeJSON(existing, settings(`Read(**/new)`), nil)
	if err != nil {
		t.Fatal(err)
	}
	got := denyList(t, merged)
	for _, want := range []string{`Read(**/secrets*)`, `Read(**/mine)`, `Read(**/new)`} {
		if !slices.Contains(got, want) {
			t.Errorf("%q is not in %v", want, got)
		}
	}
}

// A rule still backed by an entry is rendered again, so it is in both the
// record and this run's output and stays put.
func TestAMergeKeepsARuleItStillRenders(t *testing.T) {
	rule := `Read(**/id_rsa)`
	merged, err := mergeJSON(settings(rule), settings(rule), []string{rule})
	if err != nil {
		t.Fatal(err)
	}
	if got := denyList(t, merged); !slices.Contains(got, rule) {
		t.Errorf("a rule this run renders was removed: %v", got)
	}
}

// The record round-trips, and an entry that renders nothing is dropped rather
// than left empty.
func TestTheWrittenRecordRoundTripsPerFile(t *testing.T) {
	dir := t.TempDir()
	const claude, opencode = "/home/op/.claude/settings.json", "/home/op/.config/opencode/opencode.json"

	if err := recordWrittenRules(dir, claude, []string{"b", "a", "a"}); err != nil {
		t.Fatal(err)
	}
	if err := recordWrittenRules(dir, opencode, []string{"x"}); err != nil {
		t.Fatal(err)
	}
	got := readWrittenRules(dir)
	if want := []string{"a", "b"}; !slices.Equal(got[claude], want) {
		t.Errorf("claude = %v, want %v sorted and deduplicated", got[claude], want)
	}
	if !slices.Equal(got[opencode], []string{"x"}) {
		t.Errorf("opencode = %v", got[opencode])
	}
	// A file that renders nothing keeps no entry.
	if err := recordWrittenRules(dir, claude, nil); err != nil {
		t.Fatal(err)
	}
	if _, still := readWrittenRules(dir)[claude]; still {
		t.Error("a file that rendered nothing kept its entry")
	}
}

// A record that is not there, or will not parse, reads as having written
// nothing. Refusing to render over it would make this file matter more than it
// is: it is a note about what to clean up, not a boundary.
func TestAnUnreadableRecordReadsAsNothingWritten(t *testing.T) {
	dir := t.TempDir()
	if got := readWrittenRules(dir); len(got) != 0 {
		t.Errorf("a directory with no record read as %v", got)
	}
	if _, err := (fsys{}).writeFile(writtenRulesPath(dir), []byte("{not json"), 0o600, keep, keep); err != nil {
		t.Fatal(err)
	}
	if got := readWrittenRules(dir); len(got) != 0 {
		t.Errorf("a record that does not parse read as %v", got)
	}
}

// What counts as a rule faramir wrote: every string in a list, wherever the
// document puts it. The agents spell their permissions differently and one of
// them nests them two deep, so a record keyed on a particular key would miss
// whichever agent moved next.
func TestTheRecordedRulesAreEveryStringInAList(t *testing.T) {
	got := jsonStrings([]byte(`{
	  "permissions": {"deny": ["b", "a"], "allow": ["c"]},
	  "nested": {"deeper": {"list": ["d"]}},
	  "objects": [{"command": "not-a-rule"}],
	  "scalar": "not-in-a-list",
	  "number": 1
	}`))
	if want := []string{"a", "b", "c", "d"}; !slices.Equal(got, want) {
		t.Errorf("jsonStrings = %v, want %v", got, want)
	}
}

// The whole of it, through the write path: a first run records what it wrote,
// and a second run whose config no longer declares an entry takes that entry's
// rule back out while leaving the operator's own line and its own store alone.
func TestASecondRunRemovesTheRuleTheConfigStoppedDeclaring(t *testing.T) {
	home := t.TempDir()
	configDir := t.TempDir()
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}
	run := func(rules ...string) []string {
		t.Helper()
		render := func(agentFile) ([]byte, error) { return settings(rules...), nil }
		if _, _, err := writeAgentFiles(
			fsys{}, nil, home, configDir, os.Getuid(), keep, 0o700, false, render, files); err != nil {
			t.Fatal(err)
		}
		body, err := os.ReadFile(filepath.Join(home, ".claude/settings.json"))
		if err != nil {
			t.Fatal(err)
		}
		return denyList(t, body)
	}

	// The operator's own rule, put there before faramir ever wrote to the file.
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".claude/settings.json"),
		settings(`Read(**/mine)`), 0o640); err != nil {
		t.Fatal(err)
	}

	first := run(`Read(**/secrets*)`, `Read(`+configDir+`/secrets/**)`)
	for _, want := range []string{`Read(**/secrets*)`, `Read(**/mine)`} {
		if !slices.Contains(first, want) {
			t.Fatalf("after the first run %q is missing: %v", want, first)
		}
	}
	if got := readWrittenRules(configDir); len(got) == 0 {
		t.Fatal("the first run recorded nothing it wrote")
	}

	// The entry behind the first rule is gone from the config.
	second := run(`Read(` + configDir + `/secrets/**)`)
	if slices.Contains(second, `Read(**/secrets*)`) {
		t.Errorf("the rule for a removed entry survived the re-render: %v", second)
	}
	if !slices.Contains(second, `Read(`+configDir+`/secrets/**)`) {
		t.Errorf("this install's own store was removed: %v", second)
	}
	if !slices.Contains(second, `Read(**/mine)`) {
		t.Errorf("the operator's own rule was removed: %v", second)
	}
}

// The record is a read-modify-write, and it lost the same way the config and
// the enrolment record did: two runs each read the file, each add their own
// entry, and the second write drops the first. What goes with a lost entry is
// doctor's ability to tell faramir's rules from the operator's in that file,
// so it stops offering to clean them up.
func TestRecordingRulesRefusesToClobberAnotherRun(t *testing.T) {
	dir := t.TempDir()
	const mine, theirs = "/home/op/.claude/settings.json", "/home/op/.config/opencode/opencode.json"

	if err := recordWrittenRules(dir, mine, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	// What a second run holds: the record as it was before the first wrote.
	before, err := writtenRulesDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := recordWrittenRules(dir, theirs, []string{"b"}); err != nil {
		t.Fatal(err)
	}

	// The first run writing now would drop the entry the second added.
	body, err := json.MarshalIndent(map[string][]string{mine: {"a", "c"}}, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	_, err = fsys{}.writeFileExpecting(writtenRulesPath(dir), append(body, '\n'), 0o600, before)
	if err == nil {
		t.Fatal("a stale write was accepted, so the other run's entry is gone")
	}
	if !strings.Contains(err.Error(), "changed while this was working on it") {
		t.Errorf("error is %q, want it to say the file moved under it", err)
	}

	// And both entries are still there.
	written := readWrittenRules(dir)
	for _, path := range []string{mine, theirs} {
		if len(written[path]) == 0 {
			t.Errorf("%s lost its entry: %v", path, written)
		}
	}
}

// A first run writes the file rather than editing it, so there is nothing to
// expect and nothing to refuse.
func TestRecordingRulesWritesAFirstRecord(t *testing.T) {
	dir := t.TempDir()
	if err := recordWrittenRules(dir, "/home/op/.claude/settings.json", []string{"a"}); err != nil {
		t.Fatalf("a first record was refused: %v", err)
	}
	if got := readWrittenRules(dir); len(got) != 1 {
		t.Errorf("readWrittenRules = %v, want the one entry", got)
	}
}

// The removal branch takes the same guard as the write. This run's map is empty
// because its own read found one entry and it dropped it, so a run that added
// an entry in between would have the whole record removed under it: the branch
// that deletes the file was the one way past the digest.
func TestRemovingTheLastEntryRefusesToClobberAnotherRun(t *testing.T) {
	dir := t.TempDir()
	const mine, theirs = "/home/op/.claude/settings.json", "/home/op/.config/opencode/opencode.json"

	if err := recordWrittenRules(dir, mine, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	before, err := writtenRulesDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	// Another run adds its own entry.
	if err := recordWrittenRules(dir, theirs, []string{"b"}); err != nil {
		t.Fatal(err)
	}

	// The first run now renders nothing for its file. Against the record it
	// read, that empties the map and removes the file.
	if err := unchangedSince(dir, before); err == nil {
		t.Fatal("a stale removal was allowed, so the other run's entry goes with the file")
	}
	if got := readWrittenRules(dir); len(got[theirs]) == 0 {
		t.Errorf("%s lost its entry: %v", theirs, got)
	}
}

// And the ordinary removal still happens: a run that drops the last entry with
// nothing else having touched the record takes the file with it, so a host that
// has been uninstalled carries no record of files it no longer writes.
func TestRemovingTheLastEntryTakesTheRecordWithIt(t *testing.T) {
	dir := t.TempDir()
	const only = "/home/op/.claude/settings.json"
	if err := recordWrittenRules(dir, only, []string{"a"}); err != nil {
		t.Fatal(err)
	}
	if err := recordWrittenRules(dir, only, nil); err != nil {
		t.Fatalf("dropping the last entry was refused: %v", err)
	}
	if _, err := os.Stat(writtenRulesPath(dir)); !os.IsNotExist(err) {
		t.Errorf("the record is still there: %v", err)
	}
}
