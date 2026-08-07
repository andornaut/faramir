package protocol

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/secretref"
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

// A string cmd must be refused with guidance: the broker never invokes a shell.
func TestShellStringIsRejectedWithGuidance(t *testing.T) {
	_, err := parse(t, `{"cmd":"printenv ROUTER_PW"}`)
	if err == nil {
		t.Fatal("a shell string was accepted")
	}
	for _, want := range []string{"must be an array", "bash"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %q", want, err.Error())
		}
	}
}

func TestEmptyCmdRejected(t *testing.T) {
	if _, err := parse(t, `{"cmd":[]}`); err == nil {
		t.Fatal("an empty cmd was accepted")
	}
}

func TestNonStringArgvRejected(t *testing.T) {
	if _, err := parse(t, `{"cmd":["printenv",7]}`); err == nil {
		t.Fatal("a non-string argument was accepted")
	}
}

func TestRelativeCwdRejected(t *testing.T) {
	_, err := parse(t, `{"cmd":["ls"],"cwd":"relative/path"}`)
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("err = %v", err)
	}
}

func TestBadEnvNameRejected(t *testing.T) {
	for _, name := range []string{"1BAD", "has-dash", "has space", ""} {
		body := `{"cmd":["ls"],"env_refs":{"` + name + `":"secret://a/b"}}`
		if _, err := parse(t, body); err == nil {
			t.Errorf("accepted bad env name %q", name)
		}
	}
}

func TestReservedEnvNameRejected(t *testing.T) {
	for name := range ReservedEnv {
		body := `{"cmd":["ls"],"env_refs":{"` + name + `":"secret://a/b"}}`
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

func TestNegativeTimeoutRejected(t *testing.T) {
	for _, v := range []string{"-1", "0"} {
		if _, err := parse(t, `{"cmd":["ls"],"timeout_sec":`+v+`}`); err == nil {
			t.Errorf("accepted timeout_sec = %s", v)
		}
	}
}

// Python has to exclude bool explicitly because it is an int subclass.  Go does
// not, but the wire is JSON either way, so the case is worth pinning.
func TestBoolTimeoutRejected(t *testing.T) {
	if _, err := parse(t, `{"cmd":["ls"],"timeout_sec":true}`); err == nil {
		t.Fatal("accepted a boolean timeout")
	}
}

func TestUnknownOpRejected(t *testing.T) {
	_, err := parse(t, `{"op":"sync"}`)
	if err == nil {
		t.Fatal("the removed sync op was accepted")
	}
	if !strings.Contains(err.Error(), "unknown op") {
		t.Errorf("message = %q", err.Error())
	}
}

// status and list_secrets carry no cmd, and must not be required to.
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

// -- secret URIs ------------------------------------------------------------

func TestValidSecretURI(t *testing.T) {
	ref, err := secretref.Parse("secret://home/router/admin")
	if err != nil {
		t.Fatal(err)
	}
	if ref != "home/router/admin" {
		t.Errorf("ref = %q", ref)
	}
}

// A literal value where a ref belongs must be refused, not silently injected.
func TestLiteralValueRejected(t *testing.T) {
	for _, uri := range []string{"hunter2", "", "http://example.com/x"} {
		if _, err := secretref.Parse(uri); err == nil {
			t.Errorf("accepted a literal: %q", uri)
		}
	}
}

// A ref must start with an alphanumeric, which is what refuses a leading ".."
// or an empty first segment.
//
// A ".." in the middle ("secret://a/../b") is accepted, deliberately: a ref is
// a key into the flattened decrypted tree, never a filesystem path, so it
// resolves to a key that does not exist and comes back as unknown_secret.
func TestTraversalRejected(t *testing.T) {
	for _, uri := range []string{
		"secret://../../etc/passwd",
		"secret:///etc/passwd",
		"secret://.hidden",
		"secret://-flag",
	} {
		if _, err := secretref.Parse(uri); err == nil {
			t.Errorf("accepted a traversal: %q", uri)
		}
	}
	// Documented as harmless rather than left ambiguous.
	if _, err := secretref.Parse("secret://a/../b"); err != nil {
		t.Errorf("a mid-ref .. was refused, which upstream accepts: %v", err)
	}
}

// -- inline tokens ----------------------------------------------------------

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
