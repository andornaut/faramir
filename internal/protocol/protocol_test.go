package protocol

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/version"
)

// The version every client sends is filled in unless the body names one, since
// the broker refuses a request carrying none. The gate itself is
// TestARequestOfAnotherReleaseIsRefused.
func parse(t *testing.T, body string) (*Request, error) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("bad test json: %v", err)
	}
	if _, named := payload["version"]; !named {
		payload["version"] = version.Version
	}
	return Parse(payload)
}

// -- request parsing --------------------------------------------------------

func TestARequestWithOnlyACmdDefaultsToTheRunOp(t *testing.T) {
	req, err := parse(t, `{"cmd":["printenv","ROUTER_PW"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != "run" {
		t.Errorf("op = %q, want run (the default)", req.Op)
	}
	if strings.Join(req.Cmd, " ") != "printenv ROUTER_PW" {
		t.Errorf("cmd = %v", req.Cmd)
	}
	if req.HasCwd {
		t.Error("cwd was set when the request omitted it")
	}
}

// Everything the parser refuses, with the part of the message that says why: a
// refusal an operator cannot act on is the failure mode.
func TestRefusedRequests(t *testing.T) {
	for _, tc := range []struct {
		name  string
		body  string
		wants []string
	}{
		// The broker never invokes a shell, so the message names what does
		// work.
		{"a shell string", `{"cmd":"printenv ROUTER_PW"}`, []string{"must be an array", "bash"}},
		{"an empty cmd", `{"cmd":[]}`, nil},
		{"a non-string argument", `{"cmd":["printenv",7]}`, nil},
		{"a relative cwd", `{"cmd":["ls"],"cwd":"relative/path"}`, []string{"absolute"}},
		{"a timeout of zero", `{"cmd":["ls"],"timeout_sec":0}`, nil},
		{"a negative timeout", `{"cmd":["ls"],"timeout_sec":-1}`, nil},
		// JSON either way.
		{"a boolean timeout", `{"cmd":["ls"],"timeout_sec":true}`, nil},
		{"the removed sync op", `{"op":"sync"}`, []string{"unknown op"}},
		{"an env name starting with a digit", `{"cmd":["ls"],"env_refs":{"1BAD":"faramir://a/b"}}`, nil},
		{"an env name with a dash", `{"cmd":["ls"],"env_refs":{"has-dash":"faramir://a/b"}}`, nil},
		{"an env name with a space", `{"cmd":["ls"],"env_refs":{"has space":"faramir://a/b"}}`, nil},
		{"an empty env name", `{"cmd":["ls"],"env_refs":{"":"faramir://a/b"}}`, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := parse(t, tc.body)
			if err == nil {
				t.Fatal("accepted")
			}
			for _, want := range tc.wants {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("message does not mention %q: %q", want, err.Error())
				}
			}
		})
	}
}

// From the package itself, so a name added there is covered that day.
func TestReservedEnvNamesAreRefused(t *testing.T) {
	for name := range ReservedEnv {
		body := `{"cmd":["ls"],"env_refs":{"` + name + `":"faramir://a/b"}}`
		_, err := parse(t, body)
		if err == nil {
			t.Errorf("%s was not reserved", name)
			continue
		}
		if !strings.Contains(err.Error(), "reserved") {
			t.Errorf("%s: unhelpful message %q", name, err.Error())
		}
	}
}

// status and refs carry no cmd.
func TestStatusAndRefsCarryNoCmd(t *testing.T) {
	for _, op := range []string{"status", "refs"} {
		req, err := parse(t, `{"op":"`+op+`"}`)
		if err != nil {
			t.Errorf("%s: %v", op, err)
			continue
		}
		if req.Op != op {
			t.Errorf("op = %q, want %q", req.Op, op)
		}
	}
}

// -- responses --------------------------------------------------------------

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
