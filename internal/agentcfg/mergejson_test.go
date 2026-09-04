package agentcfg

import (
	"bytes"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// The one spelling these files have. jsonString renders a value into an asset
// and MergeJSON writes that asset to disk, so a character the two escape
// differently is one the file flips back and forth on: rendered one way,
// written the other, and reported as changed on every run for as long as a rule
// carries one. <, > and & are the three encoding/json escapes by default and
// the three faramir does not.
//
// Asserted on the bytes rather than on the parsed value, which is the whole
// point: both spellings parse to the same string, so nothing downstream
// notices, and the file churns anyway.
func TestTheRenderedAssetAndTheMergeAgreeOnEscaping(t *testing.T) {
	const awkward = `Read(//home/op/R&D/<draft>.key)`

	rendered := jsonString(awkward)
	for _, escape := range []string{"\\u0026", "\\u003c", "\\u003e"} {
		if strings.Contains(rendered, escape) {
			t.Errorf("jsonString emitted %s: %s", escape, rendered)
		}
	}

	document := []byte(`{"permissions":{"deny":[` + rendered + `]}}`)
	merged, err := MergeJSON(document, document, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), awkward) {
		t.Errorf("the merge rewrote the rule the asset rendered:\nasset  %s\nmerged %s", rendered, merged)
	}
	// And the second pass changes nothing, which is what a host converging on an
	// untouched file does.
	again, err := MergeJSON(merged, merged, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, merged) {
		t.Errorf("merging an already-merged file changed it:\nfirst  %s\nsecond %s", merged, again)
	}
}

// decode compares parsed values rather than bytes.
func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("merged output does not parse: %v\n%s", err, data)
	}
	return out
}

// object and array are one value of a decoded document at the type the test
// expects. Checked rather than asserted: a merge that produced another shape
// is the failure under test, and it has to read as one rather than as a panic.
func object(t *testing.T, doc map[string]any, key string) map[string]any {
	t.Helper()
	value, ok := doc[key].(map[string]any)
	if !ok {
		t.Fatalf("%s = %#v, want an object", key, doc[key])
	}
	return value
}

func array(t *testing.T, doc map[string]any, key string) []any {
	t.Helper()
	value, ok := doc[key].([]any)
	if !ok {
		t.Fatalf("%s = %#v, want an array", key, doc[key])
	}
	return value
}

// The reason for merging: a stanza faramir writes nothing under survives
// enrolment. An MCP server is one such stanza, faramir registering none.
func TestMergeJSONKeepsAStanzaFaramirDoesNotWrite(t *testing.T) {
	existing := []byte(`{
	  "mcpServers": {
	    "ha-mcp": {"type": "http", "url": "http://hamcp.internal:8086/mcp"}
	  }
	}`)
	ours := []byte(`{"permissions":{"deny":["Read(/etc/faramir/age.key)"]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	doc := decode(t, merged)
	servers, ok := doc["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers is not an object: %s", merged)
	}
	if _, ok := servers["ha-mcp"]; !ok {
		t.Errorf("the operator's own server was dropped: %s", merged)
	}
	if _, ok := doc["permissions"]; !ok {
		t.Errorf("faramir's own keys were not written: %s", merged)
	}
}

// A hook naming a binary that no longer exists fails every command, so it is
// replaced rather than left beside the new one.
func TestMergeJSONReplacesStaleFaramirHook(t *testing.T) {
	existing := []byte(`{
	  "hooks": {
	    "PreToolUse": [
	      {"matcher": "Bash", "hooks": [{"type": "command",
	        "command": "/usr/local/libexec/faramir/faramir-guard", "timeout": 10}]}
	    ]
	  }
	}`)
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[{"type":"command",` +
		`"command":"/usr/local/bin/faramir guard","timeout":10}]}]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(merged), "faramir-guard") {
		t.Errorf("the stale hook survived the merge: %s", merged)
	}
	hooks := array(t, object(t, decode(t, merged), "hooks"), "PreToolUse")
	if len(hooks) != 1 {
		t.Errorf("PreToolUse has %d entries, want 1: %s", len(hooks), merged)
	}
}

// A hook of the operator's own, in a tree whose path holds the word. What
// makes an entry faramir's is the program it invokes, not that its text
// mentions the project: a checkout under a directory named faramir names that
// path in every hook it registers, and dropping those would delete the
// operator's own configuration on every enrolment.
func TestMergeJSONKeepsAHookUnderAFaramirPath(t *testing.T) {
	existing := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Write","hooks":` +
		`[{"type":"command","command":"/home/op/src/github.com/andornaut/faramir/scripts/lint.sh"}]}]}}`)
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), "lint.sh") {
		t.Errorf("the operator's own hook was dropped: %s", merged)
	}
	// The positive control: faramir's own is still the one entry it adds, so this
	// does not pass by having stopped recognising anything.
	hooks := array(t, object(t, decode(t, merged), "hooks"), "PreToolUse")
	if len(hooks) != 2 {
		t.Errorf("PreToolUse has %d entries, want 2: %s", len(hooks), merged)
	}
}

// The operator's own hook, added to the matcher group faramir wrote rather than
// to one of its own. Groups are keyed by matcher, so that is the ordinary edit:
// dropping the group over faramir's entry inside it would take theirs with it.
func TestMergeJSONKeepsAHookSharingFaramirsGroup(t *testing.T) {
	existing := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[` +
		`{"type":"command","command":"/usr/local/bin/faramir guard"},` +
		`{"type":"command","command":"/usr/local/bin/audit-log"}]}]}}`)
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":[` +
		`{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(merged), "audit-log") {
		t.Errorf("the operator's hook was dropped with faramir's group: %s", merged)
	}
	// The positive control: faramir's own entry is there once, not twice. The
	// stale one is pruned out of the operator's group and re-added as its own.
	if got := strings.Count(string(merged), "faramir guard"); got != 1 {
		t.Errorf("faramir's hook appears %d times, want 1: %s", got, merged)
	}
}

// An argv is ordered and positional, so faramir's replaces what is there. A
// union leaves the program an earlier release installed standing as the new
// one's first argument, and what runs is neither.
func TestMergeJSONReplacesArgvRatherThanUnioningIt(t *testing.T) {
	existing := []byte(`{"hooks":{"faramir":{"type":"local",` +
		`"command":["/usr/local/libexec/faramir/faramir-hook"],"enabled":true}}}`)
	ours := []byte(`{"hooks":{"faramir":{"type":"local",` +
		`"command":["/usr/local/bin/faramir","guard"],"enabled":true}}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(merged), "faramir-hook") {
		t.Errorf("the old argv survived beside the new one: %s", merged)
	}
	command := array(t, object(t, object(t, decode(t, merged), "hooks"), "faramir"), "command")
	if len(command) != 2 || command[0] != "/usr/local/bin/faramir" {
		t.Errorf("command = %#v, want the argv this run writes: %s", command, merged)
	}
}

// The operator's own hook is not faramir's to remove. Both run.
func TestMergeJSONKeepsForeignHook(t *testing.T) {
	existing := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/audit-log"}]}]}}`)
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	hooks := array(t, object(t, decode(t, merged), "hooks"), "PreToolUse")
	if len(hooks) != 2 {
		t.Fatalf("PreToolUse has %d entries, want 2: %s", len(hooks), merged)
	}
	if !strings.Contains(string(merged), "audit-log") {
		t.Errorf("the operator's own hook was dropped: %s", merged)
	}
}

// Strings carry their own identity and union.
func TestMergeJSONUnionsDenyRules(t *testing.T) {
	existing := []byte(`{"permissions":{"deny":["Read(**/*.sops.yml)","Read(/srv/private/**)"]}}`)
	ours := []byte(`{"permissions":{"deny":["Read(**/*.sops.yml)","Read(**/age.key)"]}}`)

	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	deny := array(t, object(t, decode(t, merged), "permissions"), "deny")
	counts := map[string]int{}
	for _, rule := range deny {
		text, ok := rule.(string)
		if !ok {
			t.Fatalf("a deny rule is %#v, want a string", rule)
		}
		counts[text]++
	}
	for _, tc := range []struct {
		rule string
		want int
		why  string
	}{
		{"Read(**/*.sops.yml)", 1, "in both, must not double"},
		{"Read(/srv/private/**)", 1, "the operator's, must survive"},
		{"Read(**/age.key)", 1, "faramir's, must be added"},
	} {
		if counts[tc.rule] != tc.want {
			t.Errorf("%q appears %d times, want %d (%s): %s",
				tc.rule, counts[tc.rule], tc.want, tc.why, merged)
		}
	}
}

// The same bytes, or every install reports a change and the file churns.
func TestMergeJSONIsIdempotent(t *testing.T) {
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]},` +
		`"permissions":{"deny":["Read(**/age.key)"]}}`)
	existing := []byte(`{"permissions":{"deny":["Read(/srv/private/**)"]},"model":"opus"}`)

	once, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := MergeJSON(once, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(once) != string(twice) {
		t.Errorf("merging twice differs from merging once:\n%s\n---\n%s", once, twice)
	}
	if _, ok := decode(t, once)["model"]; !ok {
		t.Errorf("an unrelated top-level key was dropped: %s", once)
	}
}

// An empty file has nothing to preserve, and what is written is still the
// merged form rather than the asset as authored: the next run merges into what
// is there, so a first write that skipped the merge would differ from every
// write after it and settle only on the second run.
func TestMergeJSONAcceptsEmptyFileAndNormalisesIt(t *testing.T) {
	ours := []byte(`{"mcpServers":{"faramir":{"command":"/usr/local/bin/faramir"}}}`)
	merged, err := MergeJSON([]byte("  \n"), ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	var got, want any
	if err := json.Unmarshal(merged, &got); err != nil {
		t.Fatalf("the merge of an empty file is not JSON: %v", err)
	}
	if err := json.Unmarshal(ours, &want); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("merged = %s, want the same content as %s", merged, ours)
	}
	// And it is what merging into itself would produce, which is the property
	// that makes a second run a no-op.
	again, err := MergeJSON(merged, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(merged) {
		t.Errorf("a second merge changed it:\n%s\nto\n%s", merged, again)
	}
}

// Blocked rather than overwritten: replacing it would lose the operator's whole
// configuration to a stray comma.
func TestMergeJSONRefusesUnparseableFile(t *testing.T) {
	_, err := MergeJSON([]byte(`{"hooks": [},`), []byte(`{"a":1}`), nil)
	if err == nil {
		t.Fatal("no error merging into a file that does not parse")
	}
	if !strings.Contains(err.Error(), "already there") {
		t.Errorf("error does not say which side failed: %v", err)
	}
}
