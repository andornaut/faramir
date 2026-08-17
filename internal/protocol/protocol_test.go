package protocol

import (
	"encoding/json"
	"strings"
	"testing"
)

func parse(t *testing.T, body string) (*Request, error) {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal([]byte(body), &payload); err != nil {
		t.Fatalf("bad test json: %v", err)
	}
	return Parse(payload)
}

// -- request parsing --------------------------------------------------------

func TestMinimal(t *testing.T) {
	req, err := parse(t, `{"cmd":["printenv","ROUTER_PW"]}`)
	if err != nil {
		t.Fatal(err)
	}
	if req.Op != "exec" {
		t.Errorf("op = %q, want exec (the default)", req.Op)
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

// status and list_secrets carry no cmd.
func TestOpsWithoutCmd(t *testing.T) {
	for _, op := range []string{"status", "list_secrets"} {
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
