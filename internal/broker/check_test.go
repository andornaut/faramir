package broker

// The --check path.

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCheckPrintsOneJSONObject(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	body, code := s.CheckOutput()
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, body)
	}
	if _, ok := out["secrets"]; !ok {
		t.Errorf("no secrets key: %s", body)
	}
}

func TestCheckNamesTheRefusedRefsAndTheReason(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	body, _ := s.CheckOutput()
	if !strings.Contains(string(body), "tiny") {
		t.Errorf("the refused ref was not named: %s", body)
	}
	if !strings.Contains(string(body), "shorter than") {
		t.Errorf("the reason was not given: %s", body)
	}
}

// The config parses, but a command injecting that ref fails at runtime.
func TestCheckExitsNonZeroWhenARefWasRefused(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	if _, code := s.CheckOutput(); code == 0 {
		t.Error("--check succeeded with a refused ref")
	}
}
