// Package protocol implements the wire protocol: newline-delimited JSON, one
// request, one response.  See docs/protocol.md.
//
// Two rules:
//
//   - Secrets are injected as environment variables only.  A value in argv
//     shows up in ps, /proc/<pid>/cmdline and the child's error messages.
//   - cmd is an array; the broker never hands a string to "sh -c".  A caller
//     wanting a pipeline sends ["bash", "-lc", "..."], so the audit log shows
//     what ran.
package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/secretref"
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvName reports whether name can be an environment variable.  Exported so
// the CLI can refuse one where it can still name the file and line.
func ValidEnvName(name string) bool { return envNameRe.MatchString(name) }

// ReservedEnv names the broker sets itself; a caller may not overwrite them.
// SSH_AUTH_SOCK is here because rebinding it would decide what the child
// authenticates against.  FARAMIR_ESCALATION_TOKEN is here for the same reason one
// step on: it names the run an escalation is decided about, so a caller
// overwriting it decides which run its sudo asks the broker about (in practice
// only breaking its own, the value being an opaque stored secret rather than
// another run's token), but the broker owns it and no caller sets it.
// SUDO_ASKPASS stays reserved defensively: our PAM service does not consult it,
// but a child pointing sudo's askpass at a helper of its own has no business
// doing so through an injected value.
var ReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"IFS": true, "BASH_ENV": true, "ENV": true, "SOPS_AGE_KEY": true,
	"SOPS_AGE_KEY_FILE": true, "CREDENTIALS_DIRECTORY": true,
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true,
	"SUDO_ASKPASS": true, "FARAMIR_ESCALATION_TOKEN": true,
}

// Ops is every op this socket accepts, and the only reason it is exported is
// that each of them can reach the audit log: `faramir logs` renders the op in a
// fixed-width column and has to be held to the widest name here.
//
// escalations and approve are the escalation channel, and the only ops the
// broker refuses to anything but root.  They are on this socket rather than one
// of their own because the check that matters is SO_PEERCRED, which every
// connection here already carries; a second socket would be a second mode to
// get wrong.
var Ops = []string{"exec", "secret_refs", "redact", "status", "escalations", "approve", "escalate"}

type Request struct {
	Op         string
	Cmd        []string
	Cwd        string
	HasCwd     bool
	EnvRefs    map[string]string
	TimeoutSec int
	// Text is what the redact op scrubs.  Only that op reads it.
	Text string
	// More marks a redact chunk that is not the last of a stream, so the
	// redactor holds its tail back for the chunk that follows instead of
	// flushing it.  Absent on the ordinary one-shot request.
	More bool

	// ID names the escalation question `approve` answers, and Approve is the
	// answer.  WaitSec is how long `escalations` may block before returning an
	// empty list, so a watcher costs one connection rather than a poll a second.
	ID      string
	Approve bool
	WaitSec int
	// AwaitLogID names the run an `escalations` caller approved and is waiting to
	// hear the end of.  Only that run's outcome is reported back, which is what
	// lets the broker leave the last one filled rather than emptying it when it is
	// read: a caller that approved nothing is told nothing, and a filled slot does
	// not return from every poll at once.
	AwaitLogID string
	// Token names the brokered command the `escalate` op asks about.  It is an
	// identifier, not a credential: the op that reads it is refused to anything
	// but root.
	Token string
}

// Parse validates a decoded request payload.
//
// One step per field, in the order the errors are worth reading in: what the op
// is, then what it needs, then what any op may carry.  Each step reports the
// first thing wrong with its own field and nothing about the others, so a
// caller fixes one thing at a time.
func Parse(payload map[string]any) (*Request, error) {
	req := &Request{Op: "exec", EnvRefs: map[string]string{}}
	for _, step := range []func(map[string]any, *Request) error{
		parseOp, parseCmd, parseRedact, parseCwd, parseEnvRefs,
		parseEscalations, parseApprove, parseEscalate, parseWaits,
	} {
		if err := step(payload, req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// parseOp settles which op this is, every other step being about what that op
// carries.  Absent means exec, which is what a caller sending only a command
// means.
func parseOp(payload map[string]any, req *Request) error {
	if raw, ok := payload["op"]; ok && raw != nil {
		op, isStr := raw.(string)
		if !isStr {
			return fmt.Errorf("unknown op %v; expected one of %s", raw, strings.Join(Ops, ", "))
		}
		req.Op = op
	}
	if !slices.Contains(Ops, req.Op) {
		return fmt.Errorf("unknown op %q; expected one of %s", req.Op, strings.Join(Ops, ", "))
	}
	return nil
}

// parseCmd takes the command an exec must carry.  Every other op may carry one
// too -- it is what the audit record names the request by -- and there it is
// read for what it holds rather than required.
func parseCmd(payload map[string]any, req *Request) error {
	rawCmd, hasCmd := payload["cmd"]
	if req.Op != "exec" {
		if list, isList := rawCmd.([]any); isList {
			for _, a := range list {
				if s, isStr := a.(string); isStr {
					req.Cmd = append(req.Cmd, s)
				}
			}
		}
		return nil
	}
	if _, isStr := rawCmd.(string); isStr {
		return errors.New("'cmd' must be an array, not a string; the broker never " +
			"invokes a shell for you -- send ['bash', '-lc', '…']")
	}
	list, isList := rawCmd.([]any)
	if !hasCmd || !isList || len(list) == 0 {
		return errors.New("'cmd' must be a non-empty array of strings")
	}
	for _, a := range list {
		s, isStr := a.(string)
		if !isStr {
			return errors.New("'cmd' must contain only strings")
		}
		req.Cmd = append(req.Cmd, s)
	}
	return nil
}

// parseRedact takes the text a redact scrubs, and whether more of the stream
// follows it.
func parseRedact(payload map[string]any, req *Request) error {
	if req.Op != "redact" {
		return nil
	}
	text, isStr := payload["text"].(string)
	if !isStr {
		return errors.New("'text' must be a string")
	}
	req.Text = text
	if raw, ok := payload["more"]; ok && raw != nil {
		more, isBool := raw.(bool)
		if !isBool {
			return errors.New("'more' must be a boolean")
		}
		req.More = more
	}
	return nil
}

func parseCwd(payload map[string]any, req *Request) error {
	raw, ok := payload["cwd"]
	if !ok || raw == nil {
		return nil
	}
	cwd, isStr := raw.(string)
	if !isStr || !strings.HasPrefix(cwd, "/") {
		return errors.New("'cwd' must be an absolute path")
	}
	req.Cwd, req.HasCwd = cwd, true
	return nil
}

func parseEnvRefs(payload map[string]any, req *Request) error {
	raw, ok := payload["env_refs"]
	if !ok || raw == nil {
		return nil
	}
	m, isMap := raw.(map[string]any)
	if !isMap {
		return errors.New("'env_refs' must be an object of NAME -> faramir:// URI")
	}
	for name, uri := range m {
		if !envNameRe.MatchString(name) {
			return fmt.Errorf("invalid environment variable name: %q", name)
		}
		if ReservedEnv[name] {
			return fmt.Errorf("%s is reserved and cannot be overwritten", name)
		}
		s, isStr := uri.(string)
		if !isStr {
			return fmt.Errorf("env_refs[%s] must be a faramir:// URI string", name)
		}
		// Shape, not existence: a well-formed ref naming nothing is
		// unknown_secret.
		if _, err := secretref.Parse(s); err != nil {
			return fmt.Errorf("env_refs[%s]: %w", name, err)
		}
		req.EnvRefs[name] = s
	}
	return nil
}

// parseEscalations takes the run a watcher is waiting to hear the end of.  Absent
// is the ordinary case: a listing, and a watcher that has approved nothing yet.
func parseEscalations(payload map[string]any, req *Request) error {
	if req.Op != "escalations" {
		return nil
	}
	if raw, ok := payload["await_log_id"]; ok && raw != nil {
		id, isStr := raw.(string)
		if !isStr {
			return errors.New("'await_log_id' must name the exec record whose ending to report")
		}
		req.AwaitLogID = id
	}
	return nil
}

func parseApprove(payload map[string]any, req *Request) error {
	if req.Op != "approve" {
		return nil
	}
	id, isStr := payload["id"].(string)
	if !isStr || id == "" {
		return errors.New("'id' must name the question to answer; " +
			"`faramir escalations` lists what is waiting")
	}
	req.ID = id
	// Absent is a refusal.  Deny by default holds here too: a malformed answer
	// must not read as a yes.
	req.Approve, _ = payload["approve"].(bool)
	return nil
}

func parseEscalate(payload map[string]any, req *Request) error {
	if req.Op != "escalate" {
		return nil
	}
	token, isStr := payload["token"].(string)
	if !isStr || token == "" {
		return errors.New("'token' must name the brokered command asking to sudo")
	}
	req.Token = token
	return nil
}

// parseWaits takes the two durations any op may carry: how long a watcher may
// block, and how long a command may run.
func parseWaits(payload map[string]any, req *Request) error {
	if raw, ok := payload["wait_sec"]; ok && raw != nil {
		n, isNum := toInt(raw)
		if !isNum || n < 0 {
			return errors.New("'wait_sec' must be a non-negative integer")
		}
		req.WaitSec = n
	}
	if raw, ok := payload["timeout_sec"]; ok && raw != nil {
		n, isNum := toInt(raw)
		if !isNum || n <= 0 {
			return errors.New("'timeout_sec' must be a positive integer")
		}
		req.TimeoutSec = n
	}
	return nil
}

// toInt accepts an integral JSON number.
func toInt(raw any) (int, bool) {
	switch v := raw.(type) {
	case float64:
		if v != float64(int(v)) {
			return 0, false
		}
		return int(v), true
	case json.Number:
		n, err := v.Int64()
		if err != nil {
			return 0, false
		}
		return int(n), true
	case int64:
		return int(v), true
	case int:
		return v, true
	default:
		return 0, false
	}
}

// Response is the shape both success and failure share on the wire.
type Response map[string]any

// ErrorResponse builds the failure shape.  logID may be empty, which encodes
// as JSON null.
func ErrorResponse(code, message, logID string) Response {
	var id any
	if logID != "" {
		id = logID
	}
	return Response{
		"exit_code":  nil,
		"output":     "",
		"truncated":  false,
		"redactions": []any{},
		"log_id":     id,
		"error":      map[string]string{"code": code, "message": message},
	}
}
