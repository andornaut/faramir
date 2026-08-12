package install

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
)

// decode compares parsed values rather than bytes.
func decode(t *testing.T, data []byte) map[string]any {
	t.Helper()
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatalf("merged output does not parse: %v\n%s", err, data)
	}
	return out
}

// The reason for merging: a registration faramir knows nothing about survives
// enrolment.
func TestMergeJSONKeepsOtherServers(t *testing.T) {
	existing := []byte(`{
	  "mcpServers": {
	    "ha-mcp": {"type": "http", "url": "http://hamcp.internal:8086/mcp"}
	  }
	}`)
	ours := []byte(`{"mcpServers":{"faramir":{"command":"/usr/local/bin/faramir","args":["mcp"]}}}`)

	merged, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	servers, ok := decode(t, merged)["mcpServers"].(map[string]any)
	if !ok {
		t.Fatalf("mcpServers is not an object: %s", merged)
	}
	if _, ok := servers["ha-mcp"]; !ok {
		t.Errorf("the operator's own server was dropped: %s", merged)
	}
	if _, ok := servers["faramir"]; !ok {
		t.Errorf("faramir's server was not added: %s", merged)
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

	merged, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(merged), "faramir-guard") {
		t.Errorf("the stale hook survived the merge: %s", merged)
	}
	hooks := decode(t, merged)["hooks"].(map[string]any)["PreToolUse"].([]any)
	if len(hooks) != 1 {
		t.Errorf("PreToolUse has %d entries, want 1: %s", len(hooks), merged)
	}
}

// The operator's own hook is not faramir's to remove.  Both run.
func TestMergeJSONKeepsForeignHook(t *testing.T) {
	existing := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/audit-log"}]}]}}`)
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]}}`)

	merged, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	hooks := decode(t, merged)["hooks"].(map[string]any)["PreToolUse"].([]any)
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

	merged, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	deny := decode(t, merged)["permissions"].(map[string]any)["deny"].([]any)
	counts := map[string]int{}
	for _, rule := range deny {
		counts[rule.(string)]++
	}
	for rule, want := range map[string]int{
		"Read(**/*.sops.yml)":   1, // in both, must not double
		"Read(/srv/private/**)": 1, // the operator's, must survive
		"Read(**/age.key)":      1, // faramir's, must be added
	} {
		if counts[rule] != want {
			t.Errorf("%q appears %d times, want %d: %s", rule, counts[rule], want, merged)
		}
	}
}

// The same bytes, or every install reports a change and the file churns.
func TestMergeJSONIsIdempotent(t *testing.T) {
	ours := []byte(`{"hooks":{"PreToolUse":[{"matcher":"Bash","hooks":` +
		`[{"type":"command","command":"/usr/local/bin/faramir guard"}]}]},` +
		`"permissions":{"deny":["Read(**/age.key)"]}}`)
	existing := []byte(`{"permissions":{"deny":["Read(/srv/private/**)"]},"model":"opus"}`)

	once, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	twice, err := mergeJSON(once, ours)
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
	merged, err := mergeJSON([]byte("  \n"), ours)
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
	again, err := mergeJSON(merged, ours)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(merged) {
		t.Errorf("a second merge changed it:\n%s\nto\n%s", merged, again)
	}
}

// Refused rather than overwritten: replacing it would lose the operator's whole
// configuration to a stray comma.
func TestMergeJSONRefusesUnparseableFile(t *testing.T) {
	_, err := mergeJSON([]byte(`{"hooks": [},`), []byte(`{"a":1}`))
	if err == nil {
		t.Fatal("no error merging into a file that does not parse")
	}
	if !strings.Contains(err.Error(), "already there") {
		t.Errorf("error does not say which side failed: %v", err)
	}
}
