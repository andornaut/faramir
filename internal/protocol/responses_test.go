package protocol

// Responses.

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/version"
)

// log_id is optional, and must encode as JSON null rather than "".
func TestErrorResponseShape(t *testing.T) {
	data, err := json.Marshal(ErrorResponse("denied_example", "why", ""))
	if err != nil {
		t.Fatal(err)
	}
	var out map[string]any
	if err := json.Unmarshal(data, &out); err != nil {
		t.Fatal(err)
	}
	if out["log_id"] != nil {
		t.Errorf("log_id = %v, want null", out["log_id"])
	}
	if out["exit_code"] != nil {
		t.Errorf("exit_code = %v, want null", out["exit_code"])
	}
	if _, ok := out["redactions"].([]any); !ok {
		t.Errorf("redactions = %v, want []", out["redactions"])
	}
}

// A caller of another release is a process that outlived the install which
// replaced the binary under it. Blocked before the op, so what it is told is
// the skew rather than whichever op or field changed in between: the first is
// something to act on, the second is a symptom.
func TestARequestOfAnotherReleaseIsRefused(t *testing.T) {
	for _, tc := range []struct{ name, body, wants string }{
		{"a version that is not this one",
			`{"version":"0.1.4","cmd":["true"]}`, "faramir 0.1.4"},
		{"no version at all",
			`{"cmd":["true"]}`, "no version"},
		{"an op this release does not have, named by a caller that is older",
			`{"version":"0.1.4","op":"exec","cmd":["true"]}`, "faramir 0.1.4"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]any
			if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
				t.Fatalf("bad test json: %v", err)
			}
			_, err := Parse(payload)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range []string{tc.wants, version.Version, "restart it"} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("the message does not name %q: %v", want, err)
				}
			}
		})
	}
}

// The op is not what a stale caller is told about, so the refusal must not
// depend on the op being one this release knows.
func TestThisReleaseIsAccepted(t *testing.T) {
	req, err := parse(t, `{"version":"`+version.Version+`","op":"refs"}`)
	if err != nil {
		t.Fatal(err)
	}
	if req.Version != version.Version {
		t.Errorf("version = %q, want %q", req.Version, version.Version)
	}
}

// A field the caller sent as the wrong type is its own mistake, not a skew.
func TestAVersionThatIsNotAStringIsRefused(t *testing.T) {
	var payload map[string]any
	if err := json.Unmarshal([]byte(`{"version":14,"cmd":["true"]}`), &payload); err != nil {
		t.Fatalf("bad test json: %v", err)
	}
	_, err := Parse(payload)
	if err == nil || !strings.Contains(err.Error(), "'version' must be") {
		t.Errorf("err = %v, want the message naming the field", err)
	}
}
