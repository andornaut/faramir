// Package protocol implements the wire protocol: newline-delimited JSON, one
// request, one response. See docs/protocol.md.
//
// Two rules:
//
//   - Secrets are injected as environment variables only. A value in argv
//     shows up in ps, /proc/<pid>/cmdline and the child's error messages.
//   - cmd is an array; the broker never hands a string to "sh -c". A caller
//     wanting a pipeline sends ["bash", "-lc", "..."], so the audit log shows
//     what ran.
package protocol

import (
	"errors"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/version"
)

var envNameRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

// ValidEnvName reports whether name can be an environment variable. Exported
// so the CLI can refuse one where it can still name the file and line.
func ValidEnvName(name string) bool { return envNameRe.MatchString(name) }

// OperatorEnv names the account this host belongs to. Reserved below: the broker
// sets it, and a caller naming a different account would be telling a brokered
// command whose home to go looking in.
const OperatorEnv = "FARAMIR_OPERATOR"

// ReservedEnv names the broker sets itself; a caller may not overwrite them.
// SSH_AUTH_SOCK is here because rebinding it would decide what the child
// authenticates against. SUDO_ASKPASS is reserved defensively: the
// PAM service does not consult it, but pointing sudo's askpass at a helper of
// the child's own is not something an injected value should do.
var ReservedEnv = map[string]bool{
	"PATH": true, "HOME": true, "LD_PRELOAD": true, "LD_LIBRARY_PATH": true,
	"IFS": true, "BASH_ENV": true, "ENV": true, "SOPS_AGE_KEY": true,
	"SOPS_AGE_KEY_FILE": true, "CREDENTIALS_DIRECTORY": true,
	"SSH_AUTH_SOCK": true, "SSH_AGENT_PID": true,
	"SUDO_ASKPASS": true, OperatorEnv: true,
}

// OpRun is the op an absent one means, named once because the accepted list,
// the default and the check that a request is one all have to agree. Exported
// because the broker asks the same question of a parsed request: it is the one
// op that runs for longer than a round trip, so it is the one worth watching a
// connection for.
const OpRun = "run"

// Ops is every op this socket accepts. Exported because each can reach the
// audit log, and `faramir logs` renders the op in a fixed-width column held to
// the widest name here.
//
// escalations, approve and escalate are the escalation channel, and the only
// ops the broker refuses to anything but root. They are on this socket rather
// than one of their own because the check that matters is SO_PEERCRED, which
// every connection here already carries.
var Ops = []string{OpRun, "refs", "redact", "status", "refresh", "escalations", "answer", "escalate"}

type Request struct {
	// Version is what the caller's own binary reports, which every client sends
	// and every request is refused without.
	Version    string
	Op         string
	Cmd        []string
	Cwd        string
	HasCwd     bool
	EnvRefs    map[string]string
	TimeoutSec int
	// Text is what the redact op scrubs. Only that op reads it.
	Text string
	// More marks a redact chunk that is not the last of a stream, so the redactor
	// holds its tail back for the chunk that follows.
	More bool

	// ID names the escalation question `approve` answers, and Approve is the
	// answer. WaitSec is how long `escalations` may block before returning an
	// empty list, so a watcher costs one connection rather than a poll a
	// second.
	ID      string
	Approve bool
	WaitSec int
	// AwaitLogID names the run an `escalations` caller approved and is waiting to
	// hear the end of. Only that run's outcome is reported back, which is what
	// lets the broker leave the last one filled rather than emptying it when it
	// is read.
	AwaitLogID string
	// Procs is the ancestry above the sudo the `escalate` op asks about, most
	// recent first. Claims rather than facts, and worth something only because
	// the executor checks them against what it forked: a caller presents nothing
	// it was given, so there is nothing it could have been given to copy.
	Procs []int
}

// Parse validates a decoded request payload. One step per field, in the order
// the errors are worth reading in: what the op is, then what it needs, then
// what any op may carry.
func Parse(payload map[string]any) (*Request, error) {
	req := &Request{Op: OpRun, EnvRefs: map[string]string{}}
	for _, step := range []func(map[string]any, *Request) error{
		parseVersion, parseOp, parseCmd, parseRedact, parseCwd, parseEnvRefs,
		parseEscalations, parseAnswer, parseEscalate, parseWaits,
	} {
		if err := step(payload, req); err != nil {
			return nil, err
		}
	}
	return req, nil
}

// parseVersion settles whether the caller is of this binary's own release, and
// refuses it where it is not. Both halves of every socket are built from this
// repository and installed together, so a caller of another release is a
// process that outlived the install which replaced the binary under it.
//
// First of the steps: refused here, that caller is told what it is, and refused
// nowhere, it fails instead on whichever op or field changed under it, which
// names a symptom.
func parseVersion(payload map[string]any, req *Request) error {
	if raw, ok := payload["version"]; ok && raw != nil {
		named, isStr := raw.(string)
		if !isStr {
			return errors.New("'version' must be the version string the caller's binary reports")
		}
		req.Version = named
	}
	if why := version.Mismatch(req.Version); why != "" {
		return errors.New(why)
	}
	return nil
}

// parseOp settles which op this is. Absent means run, which is what a caller
// sending only a command means.
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

// parseCmd takes the command a run must carry. Every other op may carry one
// too, it being what the audit record names the request by, and there it is
// read rather than required.
func parseCmd(payload map[string]any, req *Request) error {
	rawCmd, hasCmd := payload["cmd"]
	if req.Op != OpRun {
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

// parseEscalations takes the run a watcher is waiting to hear the end of.
// Absent is the ordinary case: a listing, or a watcher that has approved
// nothing yet.
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

func parseAnswer(payload map[string]any, req *Request) error {
	if req.Op != "answer" {
		return nil
	}
	id, isStr := payload["id"].(string)
	if !isStr || id == "" {
		return errors.New("'id' must name the question to answer; " +
			"`faramir sudo ls` lists what is waiting")
	}
	req.ID = id
	// Absent is a rejection: a malformed answer must not read as a yes.
	req.Approve, _ = payload["approved"].(bool)
	return nil
}

func parseEscalate(payload map[string]any, req *Request) error {
	if req.Op != "escalate" {
		return nil
	}
	raw, isList := payload["procs"].([]any)
	if !isList || len(raw) == 0 {
		return errors.New("'procs' must name the processes above the sudo asking to escalate")
	}
	procs := make([]int, 0, len(raw))
	for _, entry := range raw {
		// float64 because that is what a JSON number unmarshals to. A pid below 1 is
		// not one: 0 and negatives are how kill() names a process group, and pid 1
		// is init, which no brokered command is.
		pid, isNumber := entry.(float64)
		if !isNumber || pid <= 1 || pid != float64(int(pid)) {
			return errors.New("each entry of 'procs' must be a pid")
		}
		procs = append(procs, int(pid))
	}
	req.Procs = procs
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
			// One refusal for every shape of bad value. It names both halves --
			// wholeness and magnitude -- because a fraction and a float past int64
			// arrive indistinguishable once decoded, and either correction is a
			// number the clamp below max_timeout_sec makes moot anyway.
			return errors.New("'timeout_sec' must be a positive whole number of " +
				"seconds, and every value is clamped to '[command] max_timeout_sec', " +
				"so one too large to hold buys nothing")
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

// ErrorResponse builds the failure shape. logID may be empty, which encodes as
// JSON null.
//
// Every failure names the version of the binary answering, because a request
// refused for naming another version is the one case where the caller cannot
// read the answer out of any op: the refusal comes before the op is read. It is
// what `doctor` reports skew from.
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
		"version":    version.Version,
		"error":      map[string]string{"code": code, "message": message},
	}
}
