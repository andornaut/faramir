package main

import (
	"encoding/json"
	"slices"
	"testing"

	"github.com/andornaut/faramir/internal/socktest"
	"github.com/andornaut/faramir/internal/testio"
)

// The broker answers refs with an array of bare names. The plain form prints
// one faramir:// URI per line from it, and the warning of a degraded store on
// stderr with the exit status it carries.
func TestRefsPrintsOneURIPerLine(t *testing.T) {
	socketPath := socktest.AnsweringBroker(t, map[string]any{
		"exit_code": 1, "refs": []string{"a/b", "c"}, "warning": "1 ref missing",
	})
	var stderr string
	stdout, code := testio.CaptureStdout(t, func() int {
		var result int
		stderr, result = testio.CaptureStderr(t, func() int {
			return send("refs", socketPath, map[string]any{"op": "refs"}, false, true)
		})
		return result
	})
	if want := "faramir://a/b\nfaramir://c\n"; stdout != want {
		t.Errorf("stdout = %q, want %q", stdout, want)
	}
	if want := "faramir refs: 1 ref missing\n"; stderr != want {
		t.Errorf("stderr = %q, want %q", stderr, want)
	}
	if code != 1 {
		t.Errorf("exit = %d, want 1", code)
	}
}

func TestRefsJSONCarriesTheArray(t *testing.T) {
	socketPath := socktest.AnsweringBroker(t, map[string]any{
		"exit_code": 0, "refs": []string{"a/b", "c"},
	})
	stdout, code := testio.CaptureStdout(t, func() int {
		return send("refs", socketPath, map[string]any{"op": "refs"}, true, true)
	})
	var got struct {
		Refs []string `json:"refs"`
	}
	if err := json.Unmarshal([]byte(stdout), &got); err != nil {
		t.Fatalf("JSON output: %v: %q", err, stdout)
	}
	if !slices.Equal(got.Refs, []string{"a/b", "c"}) {
		t.Errorf("refs = %q, want [a/b c]", got.Refs)
	}
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
}
