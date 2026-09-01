package broker

import (
	"errors"
	"fmt"
	"log"
	"maps"
	"math"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/resolve"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/termsafe"
)

// codeExecFailed answers every failure the executor reports, whatever code it
// named: what the caller can act on is that the command did not run.
const codeExecFailed = "exec_failed"

// The two exec failures a caller can branch on rather than read. A shell
// answers a program it could not find with 127 and one it found and could not
// run with 126, and `faramir run` gives the same numbers; `faramir redact --`
// runs its command itself and has always given them. Everything else stays
// exec_failed, which is the command not running for a reason worth reading.
const (
	codeNotFound      = "not_found"
	codeNotExecutable = "not_executable"
)

// codeBlocked is a command refused for what this host declares, under
// [[secret.block]] or [[secret.link]]. Terminal: nothing about the host will
// change to make the same command allowed, and a caller that retries is a
// caller reading the refusal as weather.
const codeBlocked = "blocked"

// splitExecCode takes the code the executor named off the front of its error.
// Only the codes it answers with: another message may carry a colon of its own,
// and cutting at the first one would take a clause with it.
func splitExecCode(text string) (string, string) {
	for _, code := range []string{codeNotExecutable, codeNotFound, codeExecFailed} {
		if rest, found := strings.CutPrefix(text, code+": "); found {
			return code, rest
		}
	}
	return codeExecFailed, text
}

// execFailureCode is which of the three a resolve failure was.
func execFailureCode(err error) string {
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		return codeNotFound
	case errors.Is(err, resolve.ErrNotExecutable):
		return codeNotExecutable
	}
	return codeExecFailed
}

// The two ops a brokered command's records carry. recordRunStarted is written
// when the child runs; recordRun is every other record about that command. The
// pair is joined by the log_id, so a reader selecting recordRun still gets one
// record per command.
const (
	recordRun        = "run"
	recordRunStarted = "run_started"
)

// execEscalation is what the escalation server has to say about a run that has
// ended: whether a sudo inside it was turned down, and how much of its duration
// was the question rather than the command.
type execEscalation struct {
	// code and reason are the last no a sudo was given, empty where it was given
	// none: sudo reports a refusal and an expiry alike, as its own authentication
	// failure.
	code, reason string
	// waited is seconds the child spent blocked inside sudo. The duration is
	// wall time from fork to exit, so an escalation answered slowly reads as a
	// slow command without it.
	waited float64
}

func (s *Server) escalationOf(runID string) execEscalation {
	code, reason := s.Escalation.Refusal(runID)
	return execEscalation{code: code, reason: reason, waited: s.Escalation.Waited(runID).Seconds()}
}

// fields is what a record carries of it, each present only where it says
// something.
func (a execEscalation) fields() map[string]any {
	out := map[string]any{}
	if a.code != "" {
		out["escalation_code"], out["escalation"] = a.code, a.reason
	}
	if a.waited > 0 {
		out["waited_sec"] = math.Round(a.waited*1000) / 1000
	}
	return out
}

// execResponse is what the caller is told about a command that ran. What the
// escalation has to say rides along, each field present only where it says
// something.
// addRunConditions sets the audit-record fields that a run carries only when
// they say something, keeping a zero off every record.
func addRunConditions(record map[string]any, result *execclient.Result) {
	// Both mean the recorded output is not what the command wrote.
	if result.InvalidBytes > 0 {
		record["invalid_bytes"] = result.InvalidBytes
	}
	// The record is the whole of what is left of an abandoned run: the response
	// goes to a connection nobody is reading.
	if result.Abandoned {
		record["abandoned"] = true
	}
	// The exit code is a stand-in: the executor went away before reporting a
	// status, so the log does not read the code as a signal kill.
	if result.StatusUnknown {
		record["status_unknown"] = true
	}
}

// okResponse is the base success shape every op answers with, the five keys
// docs/protocol.md documents; an op adds its own beside them, and the run op
// builds its response from the executor's result instead. log_id is JSON null
// where a response has no record to cite.
func okResponse(exitCode int, output string) protocol.Response {
	return protocol.Response{
		"exit_code": exitCode, "output": output, "truncated": false,
		"redactions": []any{}, "log_id": nil,
	}
}

func execResponse(logID string, judged execEscalation,
	result *execclient.Result) protocol.Response {
	response := protocol.Response{
		"exit_code": result.ExitCode, "output": result.Output,
		"truncated": result.Truncated, "redactions": result.Redactions,
		"log_id": logID, "timed_out": result.TimedOut,
		"duration_sec":  result.DurationSec,
		"invalid_bytes": result.InvalidBytes,
	}
	// Only when set: the exit code is a stand-in for a status the executor never
	// reported, so a caller is told the code is a guess rather than a signal kill.
	if result.StatusUnknown {
		response["status_unknown"] = true
	}
	maps.Copy(response, judged.fields())
	return response
}

// execAudit is what every record about one brokered command carries: which
// command, run where, against which refs, and when it started. Gathered once
// and rendered per record, so the pair sharing a log_id cannot disagree.
type execAudit struct {
	logID     string
	peer      *sockutil.Peer
	cmd       []string
	argv0Path string
	cwd       string
	refs      map[string]string
	started   time.Time
}

// execFields is one record's worth of those, less the op and the outcome, which
// are the caller's to add. Redacted afresh per record: the value set can change
// while a command runs.
func (s *Server) execFields(a execAudit) map[string]any {
	record := s.redactor()
	return map[string]any{
		"log_id": a.logID, "peer": a.peer,
		"cmd":        redactEach(record, a.cmd),
		"argv0_path": record.RedactText(a.argv0Path),
		"cwd":        record.RedactText(a.cwd),
		"env_refs":   a.refs,
		"started_at": a.started.Unix(),
	}
}

func (s *Server) opRun(request *protocol.Request, peer *sockutil.Peer,
	abandoned <-chan struct{}) protocol.Response {
	execCfg := s.Config.Command
	logID := audit.NewLogID()
	if refused := s.refuseUnreadable("run", "this command", logID, peer); refused != nil {
		return *refused
	}
	if refused := s.refuseUnauditable("this command", logID); refused != nil {
		return *refused
	}

	cmd, envRefs := request.Cmd, request.EnvRefs

	// No fallback: a brokered command runs where its caller was, and nothing else
	// knows where that is.
	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		return s.refuse("bad_request", "no cwd: name the directory to run in.",
			logID, peer, cmd, "")
	}
	// Fails early with a clear message; it enforces nothing. Permission is left
	// to the executor, whose uid may hold traversal the broker does not. Absence
	// is refused here, being knowable from any uid, though not from every mount
	// namespace: see cwdMissing.
	info, statErr := os.Stat(cwd)
	switch {
	case statErr == nil && !info.IsDir():
		return s.refuse("bad_request", "cwd is not a directory: "+cwd, logID, peer, cmd, cwd)
	case os.IsPermission(statErr):
		// The executor decides.
	case statErr != nil:
		return s.refuse("bad_request", cwdMissing(cwd), logID, peer, cmd, cwd)
	}

	// Before the program is resolved and before a slot is taken: this is a
	// refusal about what the command would disclose, not about whether it could
	// have run. The agent's own tools are already refused what this host
	// declares, and the broker is the one route left to the file.
	if rule, refused := s.declared.refuses(cmd, cwd); refused {
		return s.refuse(codeBlocked, declaredRefusal(rule), logID, peer, cmd, cwd)
	}

	argv0Path, err := resolve.Program(cmd[0], cwd, execCfg)
	if err != nil {
		// Redacted like every other agent-visible string.
		record := s.redactor()
		detail := record.RedactText(err.Error())
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": recordRun, "peer": peer,
			"cmd": redactEach(record, cmd), "cwd": record.RedactText(cwd),
			"error": detail,
		}, audit.Output{})
		return protocol.ErrorResponse(execFailureCode(err), detail, logID)
	}

	// The only place plaintext is touched outside the store, and it goes straight
	// into the child's environ. HOME is left to the executor.
	env := make(map[string]string, len(execCfg.Env)+1)
	maps.Copy(env, execCfg.Env)
	// SSH_AUTH_SOCK: the child can authenticate with the keys, not read them.
	maps.Copy(env, s.Ssh.Env())
	// The concurrency slot first, and before the run is registered: Answer counts
	// a registered run as an occupant and refuses to approve alongside it, so a
	// run about to be refused `busy` must never be one.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return s.refuse("busy", fmt.Sprintf(
			"broker is at its concurrency limit (%d); retry shortly",
			s.Config.Command.Concurrency), logID, peer, cmd, cwd)
	}

	// An id and nothing else: it goes to the executor, never into the child's
	// environment, so there is nothing inside the run to read, copy or leak.
	// FARAMIR_OPERATOR below is not part of it -- it names the host's operator,
	// which is not a secret and attributes nothing.
	// Registered before the child starts and dropped when it ends, so a late
	// request is refused rather than answered against a finished command.
	//
	// The argv is the redacted one, this reaching a terminal and the log. One
	// redactor for the whole question; the audit write below builds its own,
	// against whatever the store holds by then.
	asked := s.redactor()
	runID, heldBy := s.Escalation.Register(escalation.Run{
		Argv: redactEach(asked, cmd), Cwd: cwd, LogID: logID,
		// Who asked, which the executor's own uid does not say: every brokered
		// command runs as that one.
		Caller: callerName(peer),
		// What root would actually run, which is not always what argv[0] says: a
		// relative argv[0] resolves against the request's cwd, which is the agent's
		// working tree. The question names both when they differ.
		Argv0Path: asked.RedactText(argv0Path),
	})
	// Held while an escalation is live or a question is waiting: the two commands
	// share the executor's uid, so running this one now would give it a route to
	// the root the other was approved for.
	//
	// A terminal refusal rather than a `busy` to retry: a retryable answer makes
	// a caller poll the one window in which the host must be quiet, landing its
	// retries against the exact interval the serialisation protects.
	if heldBy != "" {
		// heldBy is a whole clause, naming the command and which of the two states
		// it is in: waiting to be approved, or holding an approval already given.
		// Framing it as a noun phrase spliced a second sentence into the first.
		return s.refuse("escalation_in_progress", heldBy+
			", and no other brokered command runs while one is: "+
			"a second could ride it. Not run and not queued; run it again once that "+
			"one has finished", logID, peer, cmd, cwd)
	}
	// How this run ended, read by the defer below and published to the terminal
	// that approved it. The zero value is a run the broker never got a status
	// for and says so: a nil ExitCode prints as an ending without one, where a
	// zero would print as a clean exit.
	outcome := escalation.Outcome{LogID: logID}
	defer func() { s.Escalation.Release(runID, outcome) }()
	// Who the host belongs to. Reserved, so a caller cannot name a different
	// account, and set on both sides of a sudo: the same value goes into the
	// grant's env_file, because sudo's env_reset would otherwise drop it exactly
	// where a command most needs to resolve the operator's home.
	if s.Config.Server.AgentUser != "" {
		env[protocol.OperatorEnv] = s.Config.Server.AgentUser
	}
	injected, why := s.inject(env, envRefs)
	if why != "" {
		// inject fills env ref by ref and can fail on a later one, so earlier
		// values are already in the map: drop them here rather than leave plaintext
		// referenced until the map is collected, as the post-exec cleanup does.
		for k := range env {
			delete(env, k)
		}
		return s.refuse("unknown_secret", why, logID, peer, cmd, cwd)
	}

	timeout := clampTimeout(request.TimeoutSec, execCfg)

	// Every known secret, not only the injected ones: a managed host can print one
	// the broker never injected.
	redactor := s.redactor()
	collector := audit.NewCollector(s.Audit.OutputBudget())
	started := time.Now()

	audited := execAudit{
		logID: logID, peer: peer, cmd: cmd, argv0Path: argv0Path,
		cwd: cwd, refs: injected, started: started,
	}

	// An exec is a pair of records sharing one log_id: this one when the child
	// starts, and the one below when it ends. Without it a command is absent
	// from the log for as long as it runs, and a run that never returns leaves
	// nothing at all. No output: there is none yet.
	starting := s.execFields(audited)
	starting["op"] = recordRunStarted
	s.Audit.Write(starting, audit.Output{})

	result, err := s.exec(redactor, collector.Add, execclient.Request{
		Argv:       append([]string{argv0Path}, cmd[1:]...),
		Cwd:        cwd,
		Env:        env,
		Stdin:      request.Stdin,
		TimeoutSec: timeout,
		RunID:      runID,
		Abandoned:  abandoned,
	})
	// Drop the plaintext as soon as the child has it; the store keeps the values.
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		// The executor names its own code in the error it returns. Taken off the
		// front rather than printed twice ("exec_failed: exec_failed:
		// /usr/bin/pwd: ..."), and carried rather than flattened: a program the
		// kernel would not run is answered as not_executable, which is what gets
		// the caller the shell's 126.
		code, text := splitExecCode(err.Error())
		detail := s.safeDetail(text)
		// Rendered on top of the redaction, which covers values and not control
		// characters: this string reaches the escalation terminal, where the next
		// thing printed is a question somebody judges.
		outcome.Error = termsafe.Line(detail)
		// The child ran whatever failed afterwards, so it is recorded before the
		// error is returned: otherwise a command that reached a managed host leaves
		// nothing behind but a daemon-log line.
		record := s.execFields(audited)
		record["op"], record["error"] = recordRun, detail
		s.Audit.Write(record, collector.Output())
		return protocol.ErrorResponse(code, detail, logID)
	}

	// Read before the deferred Release drops the run.
	judged := s.escalationOf(runID)

	outcome.ExitCode = &result.ExitCode
	outcome.DurationSec, outcome.TimedOut = result.DurationSec, result.TimedOut
	outcome.WaitedSec, outcome.StatusUnknown = judged.waited, result.StatusUnknown

	record := s.execFields(audited)
	record["op"] = recordRun
	record["exit_code"], record["duration_sec"] = result.ExitCode, result.DurationSec
	record["timed_out"], record["redactions"] = result.TimedOut, result.Redactions
	addRunConditions(record, result)
	maps.Copy(record, judged.fields())
	s.Audit.Write(record, collector.Output())

	total := 0
	for _, r := range result.Redactions {
		total += r.Count
	}
	log.Printf("%s %s exit=%d dur=%.1fs redactions=%d",
		logID, filepath.Base(argv0Path), result.ExitCode, result.DurationSec, total)

	return execResponse(logID, judged, result)
}

// inject puts the requested values into the child's environment and returns
// what each name was filled from, for the audit record: the refs, never the
// values. The string is why a ref could not be filled, empty where every one
// was.
//
// A failure stops at the ref that caused it, so env may already hold the values
// named before it. Nothing runs with them: the caller answers a non-empty
// reason with a refusal, and the map goes no further.
func (s *Server) inject(env map[string]string, envRefs map[string]string) (map[string]string, string) {
	injected := map[string]string{}
	for name, uri := range envRefs {
		ref, err := secretref.Parse(uri)
		if err != nil {
			return nil, err.Error()
		}
		value, err := s.Store.Value(ref)
		if err != nil {
			return nil, err.Error()
		}
		env[name] = value
		injected[name] = ref
	}
	return injected, ""
}

// clampTimeout is what this run actually gets: what it asked for, the config's
// default where it asked for nothing, and never more than the ceiling.
func clampTimeout(asked int, execCfg config.CommandConfig) int {
	if asked == 0 {
		asked = execCfg.TimeoutSec
	}
	return min(asked, execCfg.MaxTimeoutSec)
}
