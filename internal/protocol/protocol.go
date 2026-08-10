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
// authenticates against.  FARAMIR_ELEVATE_TOKEN is here for the same reason one
// step on: it names the run an elevation is decided about, so a caller
// overwriting it decides which run its sudo asks the broker about (in practice
// only breaking its own, the value being an opaque stored secret rather than
// another run's token -- but the broker owns it and no caller sets it).
// SUDO_ASKPASS stays reserved defensively: our PAM service does not consult it,
// but a child pointing sudo's askpass at a helper of its own has no business
// doing so through an injected value.
var ReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"IFS": true, "BASH_ENV": true, "ENV": true, "SOPS_AGE_KEY": true,
	"SOPS_AGE_KEY_FILE": true, "CREDENTIALS_DIRECTORY": true,
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true,
	"SUDO_ASKPASS": true, "FARAMIR_ELEVATE_TOKEN": true,
}

// approvals and approve are the elevation channel, and the only ops the broker
// refuses to anything but root.  They are on this socket rather than one of
// their own because the check that matters is SO_PEERCRED, which every
// connection here already carries; a second socket would be a second mode to
// get wrong.
var ops = []string{"exec", "list_secrets", "redact", "status", "approvals", "approve", "elevate"}

type Request struct {
	Op         string
	Cmd        []string
	Cwd        string
	HasCwd     bool
	EnvRefs    map[string]string
	TimeoutSec int
	// Text is what the redact op scrubs.  Only that op reads it.
	Text string

	// ID names the elevation question `approve` answers, and Approve is the
	// answer.  WaitSec is how long `approvals` may block before returning an
	// empty list, so a watcher costs one connection rather than a poll a second.
	ID      string
	Approve bool
	WaitSec int
	// Token names the brokered command the `elevate` op asks about.  It is an
	// identifier, not a credential: the op that reads it is refused to anything
	// but root.
	Token string
}

// Parse validates a decoded request payload.
func Parse(payload map[string]any) (*Request, error) {
	req := &Request{Op: "exec", EnvRefs: map[string]string{}}

	if raw, ok := payload["op"]; ok && raw != nil {
		op, isStr := raw.(string)
		if !isStr {
			return nil, fmt.Errorf("unknown op %v; expected one of %s", raw, strings.Join(ops, ", "))
		}
		req.Op = op
	}
	if !slices.Contains(ops, req.Op) {
		return nil, fmt.Errorf("unknown op %q; expected one of %s", req.Op, strings.Join(ops, ", "))
	}

	rawCmd, hasCmd := payload["cmd"]
	if req.Op == "exec" {
		if _, isStr := rawCmd.(string); isStr {
			return nil, fmt.Errorf("'cmd' must be an array, not a string; the broker never " +
				"invokes a shell for you -- send ['bash', '-lc', '…']")
		}
		list, isList := rawCmd.([]any)
		if !hasCmd || !isList || len(list) == 0 {
			return nil, fmt.Errorf("'cmd' must be a non-empty array of strings")
		}
		for _, a := range list {
			s, isStr := a.(string)
			if !isStr {
				return nil, fmt.Errorf("'cmd' must contain only strings")
			}
			req.Cmd = append(req.Cmd, s)
		}
	} else if list, isList := rawCmd.([]any); isList {
		for _, a := range list {
			if s, isStr := a.(string); isStr {
				req.Cmd = append(req.Cmd, s)
			}
		}
	}

	if req.Op == "redact" {
		text, isStr := payload["text"].(string)
		if !isStr {
			return nil, fmt.Errorf("'text' must be a string")
		}
		req.Text = text
	}

	if raw, ok := payload["cwd"]; ok && raw != nil {
		cwd, isStr := raw.(string)
		if !isStr || !strings.HasPrefix(cwd, "/") {
			return nil, fmt.Errorf("'cwd' must be an absolute path")
		}
		req.Cwd, req.HasCwd = cwd, true
	}

	if raw, ok := payload["env_refs"]; ok && raw != nil {
		m, isMap := raw.(map[string]any)
		if !isMap {
			return nil, fmt.Errorf("'env_refs' must be an object of NAME -> secret:// URI")
		}
		for name, uri := range m {
			if !envNameRe.MatchString(name) {
				return nil, fmt.Errorf("invalid environment variable name: %q", name)
			}
			if ReservedEnv[name] {
				return nil, fmt.Errorf("%s is reserved and cannot be overwritten", name)
			}
			s, isStr := uri.(string)
			if !isStr {
				return nil, fmt.Errorf("env_refs[%s] must be a secret:// URI string", name)
			}
			// Shape, not existence: a well-formed ref naming nothing is
			// unknown_secret.
			if _, err := secretref.Parse(s); err != nil {
				return nil, fmt.Errorf("env_refs[%s]: %v", name, err)
			}
			req.EnvRefs[name] = s
		}
	}

	if req.Op == "approve" {
		id, isStr := payload["id"].(string)
		if !isStr || id == "" {
			return nil, fmt.Errorf("'id' must name the question to answer; " +
				"`faramir approve` lists what is waiting")
		}
		req.ID = id
		// Absent is a refusal.  Deny by default holds here too: a malformed answer
		// must not read as a yes.
		req.Approve, _ = payload["approve"].(bool)
	}

	if req.Op == "elevate" {
		token, isStr := payload["token"].(string)
		if !isStr || token == "" {
			return nil, fmt.Errorf("'token' must name the brokered command asking to elevate")
		}
		req.Token = token
	}

	if raw, ok := payload["wait_sec"]; ok && raw != nil {
		n, isNum := toInt(raw)
		if !isNum || n < 0 {
			return nil, fmt.Errorf("'wait_sec' must be a non-negative integer")
		}
		req.WaitSec = n
	}

	if raw, ok := payload["timeout_sec"]; ok && raw != nil {
		n, isNum := toInt(raw)
		if !isNum || n <= 0 {
			return nil, fmt.Errorf("'timeout_sec' must be a positive integer")
		}
		req.TimeoutSec = n
	}

	return req, nil
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
