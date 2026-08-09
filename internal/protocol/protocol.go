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
// authenticates against.
var ReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"IFS": true, "BASH_ENV": true, "ENV": true, "SOPS_AGE_KEY": true,
	"SOPS_AGE_KEY_FILE": true, "CREDENTIALS_DIRECTORY": true,
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true,
}

var ops = []string{"exec", "list_secrets", "redact", "status"}

// Error is a malformed request.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

type Request struct {
	Op         string
	Cmd        []string
	Cwd        string
	HasCwd     bool
	EnvRefs    map[string]string
	TimeoutSec int
	// Text is what the redact op scrubs.  Only that op reads it.
	Text string
}

// Parse validates a decoded request payload.
func Parse(payload map[string]any) (*Request, error) {
	req := &Request{Op: "exec", EnvRefs: map[string]string{}}

	if raw, ok := payload["op"]; ok && raw != nil {
		op, isStr := raw.(string)
		if !isStr {
			return nil, errf("unknown op %v; expected one of %s", raw, strings.Join(ops, ", "))
		}
		req.Op = op
	}
	if !slices.Contains(ops, req.Op) {
		return nil, errf("unknown op %q; expected one of %s", req.Op, strings.Join(ops, ", "))
	}

	rawCmd, hasCmd := payload["cmd"]
	if req.Op == "exec" {
		if _, isStr := rawCmd.(string); isStr {
			return nil, errf("'cmd' must be an array, not a string; the broker never " +
				"invokes a shell for you -- send ['bash', '-lc', '…']")
		}
		list, isList := rawCmd.([]any)
		if !hasCmd || !isList || len(list) == 0 {
			return nil, errf("'cmd' must be a non-empty array of strings")
		}
		for _, a := range list {
			s, isStr := a.(string)
			if !isStr {
				return nil, errf("'cmd' must contain only strings")
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
			return nil, errf("'text' must be a string")
		}
		req.Text = text
	}

	if raw, ok := payload["cwd"]; ok && raw != nil {
		cwd, isStr := raw.(string)
		if !isStr || !strings.HasPrefix(cwd, "/") {
			return nil, errf("'cwd' must be an absolute path")
		}
		req.Cwd, req.HasCwd = cwd, true
	}

	if raw, ok := payload["env_refs"]; ok && raw != nil {
		m, isMap := raw.(map[string]any)
		if !isMap {
			return nil, errf("'env_refs' must be an object of NAME -> secret:// URI")
		}
		for name, uri := range m {
			if !envNameRe.MatchString(name) {
				return nil, errf("invalid environment variable name: %q", name)
			}
			if ReservedEnv[name] {
				return nil, errf("%s is reserved and cannot be overwritten", name)
			}
			s, isStr := uri.(string)
			if !isStr {
				return nil, errf("env_refs[%s] must be a secret:// URI string", name)
			}
			// Shape, not existence: a well-formed ref naming nothing is
			// unknown_secret.
			if _, err := secretref.Parse(s); err != nil {
				return nil, errf("env_refs[%s]: %v", name, err)
			}
			req.EnvRefs[name] = s
		}
	}

	if raw, ok := payload["timeout_sec"]; ok && raw != nil {
		n, isNum := toInt(raw)
		if !isNum || n <= 0 {
			return nil, errf("'timeout_sec' must be a positive integer")
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
