// Package protocol implements the wire protocol: newline-delimited JSON, one
// request, one response.
//
// Two rules that are not negotiable:
//
//   - Secrets are injected as environment variables only.  There is no way to
//     ask for a value to be substituted into argv: a value in argv shows up in
//     ps output, in /proc/<pid>/cmdline, and in the child's own error messages.
//   - cmd is an array.  The broker never passes a string to "sh -c".  A caller
//     who wants a pipeline sends ["bash", "-lc", "..."] explicitly, so what is
//     being run is visible in the audit log rather than buried in a string the
//     broker handed to a shell.
package protocol

import (
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/secretref"
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ReservedEnv names the broker sets itself; a caller may not overwrite them.
var ReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"IFS": true, "BASH_ENV": true, "ENV": true, "SOPS_AGE_KEY": true,
	"SOPS_AGE_KEY_FILE": true, "CREDENTIALS_DIRECTORY": true,
}

var ops = []string{"exec", "list_secrets", "status"}

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

// toInt accepts a JSON number that is integral.  A bool is not a number here,
// unlike in Python where bool is an int subclass and has to be excluded.
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

var nonAlnum = regexp.MustCompile(`[^A-Za-z0-9]+`)

// EnvNameForRef is the deterministic variable name for an inline {{SECRET:…}}
// token.
func EnvNameForRef(ref string) string {
	return "FARAMIR_" + strings.Trim(strings.ToUpper(nonAlnum.ReplaceAllString(ref, "_")), "_")
}

// ResolveInlineTokens rewrites {{SECRET:ref}} in argv into a shell variable
// reference.
//
// The token is a readability affordance for the caller.  It never expands to a
// value here: it becomes ${VAR}, and VAR is added to the injected environment.
// If the caller already bound that ref to a name, that name is reused.  This
// only expands if the program itself is a shell, which is the point: the value
// still never appears in any argv.
func ResolveInlineTokens(cmd []string, envRefs map[string]string) ([]string, map[string]string, error) {
	byRef := map[string]string{}
	for name, uri := range envRefs {
		ref, err := secretref.Parse(uri)
		if err != nil {
			return nil, nil, err
		}
		byRef[ref] = name
	}
	merged := make(map[string]string, len(envRefs))
	maps.Copy(merged, envRefs)

	rewritten := make([]string, 0, len(cmd))
	for _, arg := range cmd {
		out := secretref.InlineTokenRe.ReplaceAllStringFunc(arg, func(m string) string {
			ref := secretref.InlineTokenRe.FindStringSubmatch(m)[1]
			name, ok := byRef[ref]
			if !ok {
				name = EnvNameForRef(ref)
				byRef[ref] = name
				merged[name] = "secret://" + ref
			}
			return "${" + name + "}"
		})
		rewritten = append(rewritten, out)
	}
	return rewritten, merged, nil
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
