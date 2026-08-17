package server

import (
	"encoding/json"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/executor"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
)

// errorMessage is the message of a refusal response.  Checked rather than
// asserted: a response of another shape is the failure under test.
func errorMessage(t *testing.T, r map[string]any) string {
	t.Helper()
	fields, ok := r["error"].(map[string]string)
	if !ok {
		t.Fatalf("error = %#v, want map[string]string", r["error"])
	}
	return fields["message"]
}

// These cover what the broker decides around a child process (the timeout, the
// environment, the audit record, the concurrency limit) without a socket, a PTY
// or a fork.

// recorder stands in for the executor: it captures the request and returns a
// canned result.  Env is snapshotted because the broker wipes the map once the
// child holds the values; liveEnv keeps the original so the wipe can be
// asserted on.
type recorder struct {
	mu       sync.Mutex
	requests []executor.Request
	liveEnv  []map[string]string
	output   string
	result   *executor.Result
	err      error
}

func (rec *recorder) install(s *Server) *recorder {
	s.exec = func(r *redact.Redactor, sink func(string), req executor.Request) (*executor.Result, error) {
		rec.mu.Lock()
		recorded := req
		recorded.Env = maps.Clone(req.Env)
		rec.requests = append(rec.requests, recorded)
		rec.liveEnv = append(rec.liveEnv, req.Env)
		rec.mu.Unlock()
		if rec.err != nil {
			return nil, rec.err
		}
		// Through the real redactor into both the result and the sink, as the
		// real executor does: same text, capped differently.
		var emitted strings.Builder
		if rec.output != "" {
			if safe := r.Feed(rec.output); safe != "" {
				emitted.WriteString(safe)
				sink(safe)
			}
			if final := r.Flush(); final != "" {
				emitted.WriteString(final)
				sink(final)
			}
		}
		if rec.result != nil {
			return rec.result, nil
		}
		return &executor.Result{
			ExitCode: 0, Output: emitted.String(), Redactions: r.Summary(),
		}, nil
	}
	return rec
}

// none asserts the executor was never reached.
func (rec *recorder) none(t *testing.T) {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.requests) != 0 {
		t.Errorf("the command ran anyway: %+v", rec.requests)
	}
}

func (rec *recorder) only(t *testing.T) executor.Request {
	t.Helper()
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(rec.requests))
	}
	return rec.requests[0]
}

const goodValue = "hunter2-correct-horse"

func execServer(t *testing.T) (*Server, *recorder) {
	t.Helper()
	s := newServer(t, map[string]string{"a/b": goodValue, "tiny": "abc"})
	return s, (&recorder{}).install(s)
}

// A directory is filled in unless the test named one, since the broker refuses
// a request carrying none.
func exec(t *testing.T, s *Server, request map[string]any) protocol.Response {
	t.Helper()
	if _, ok := request["cwd"]; !ok {
		request["cwd"] = os.TempDir()
	}
	return execAsGiven(t, s, request)
}

// The request verbatim, for the tests that are about the cwd itself.
func execAsGiven(t *testing.T, s *Server, request map[string]any) protocol.Response {
	t.Helper()
	if _, ok := request["op"]; !ok {
		request["op"] = "exec"
	}
	return s.Handle(request, &sockutil.Peer{PID: 1, UID: 1000, GID: 1000})
}

func errorCode(t *testing.T, r protocol.Response) string {
	t.Helper()
	e, ok := r["error"].(map[string]string)
	if !ok {
		t.Fatalf("response carries no error: %v", r)
	}
	return e["code"]
}

// -- the timeout ------------------------------------------------------------

// No timeout gets the configured default; more than max_timeout_sec is clamped
// rather than refused.  The clamp is the only bound on how long a command holds
// a concurrency slot.
func TestTimeoutDefaultsAndClamps(t *testing.T) {
	for _, tc := range []struct {
		name  string
		asked any
		want  int
	}{
		{"omitted takes the default", nil, 30},
		{"under the ceiling is honoured", 10, 10},
		{"over the ceiling is clamped", 9000, 60},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, rec := execServer(t)
			request := map[string]any{"cmd": []any{"true"}}
			if asked, ok := tc.asked.(int); ok {
				request["timeout_sec"] = float64(asked)
			}
			if r := exec(t, s, request); r["error"] != nil {
				t.Fatalf("error: %v", r["error"])
			}
			if got := rec.only(t).TimeoutSec; got != tc.want {
				t.Errorf("timeout_sec = %d, want %d", got, tc.want)
			}
		})
	}
}

// -- the child's environment ------------------------------------------------

// env plus exactly the refs asked for.  HOME is absent: it belongs to the
// executor's uid, which supplies it.
//
// This is the map the broker builds, not the child's environment; that is
// asserted against a real child in tests/e2e/check-exec.sh.
func TestTheEnvironmentTheBrokerAssembles(t *testing.T) {
	s, rec := execServer(t)
	r := exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "faramir://a/b"},
	})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	env := rec.only(t).Env

	if env["PATH"] != "/usr/bin:/bin" {
		t.Errorf("PATH = %q; env did not reach the child", env["PATH"])
	}
	if env["ROUTER_PW"] != goodValue {
		t.Errorf("the ref was not injected: %q", env["ROUTER_PW"])
	}
	if _, ok := env["HOME"]; ok {
		t.Error("HOME was set by the broker; it belongs to the executor's uid")
	}
	// Nothing beyond env and the refs.
	if len(env) != len(s.Config.Command.Env)+1 {
		t.Errorf("environment = %v, want env plus ROUTER_PW only", env)
	}
}

// The assembled map is wiped once the child holds the values, so no plaintext
// copy outlives the request.
func TestTheAssembledEnvironmentIsWipedAfterTheRun(t *testing.T) {
	s, rec := execServer(t)
	exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "faramir://a/b"},
	})
	rec.mu.Lock()
	defer rec.mu.Unlock()
	if len(rec.liveEnv) != 1 {
		t.Fatalf("got %d runs, want 1", len(rec.liveEnv))
	}
	if len(rec.liveEnv[0]) != 0 {
		t.Errorf("the assembled environment survived the request: %v", rec.liveEnv[0])
	}
}

// -- refs -------------------------------------------------------------------

func TestUnknownAndRefusedRefsAreDistinguished(t *testing.T) {
	for _, tc := range []struct{ name, uri, want string }{
		{"unknown", "faramir://nope", "unknown secret ref"},
		{"refused at load", "faramir://tiny", "refused at load"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := execServer(t)
			r := exec(t, s, map[string]any{
				"cmd": []any{"true"}, "env_refs": map[string]any{"X": tc.uri},
			})
			if code := errorCode(t, r); code != "unknown_secret" {
				t.Fatalf("code = %q", code)
			}
			msg := errorMessage(t, r)
			if !strings.Contains(msg, tc.want) {
				t.Errorf("message %q does not say %q", msg, tc.want)
			}
		})
	}
}

// A ref that cannot be resolved must not reach the executor at all.
func TestABadRefStopsTheCommandRunning(t *testing.T) {
	s, rec := execServer(t)
	exec(t, s, map[string]any{
		"cmd": []any{"true"}, "env_refs": map[string]any{"X": "faramir://nope"},
	})
	rec.none(t)
}

// -- cwd --------------------------------------------------------------------

// Nothing to default to: a brokered command runs where its caller was.
func TestARequestWithNoCwdIsRefused(t *testing.T) {
	s, rec := execServer(t)
	r := execAsGiven(t, s, map[string]any{"cmd": []any{"true"}})
	if code := errorCode(t, r); code != "bad_request" {
		t.Fatalf("code = %q", code)
	}
	rec.none(t)
}

func TestAMissingCwdIsRefusedBeforeAnythingRuns(t *testing.T) {
	s, rec := execServer(t)
	r := exec(t, s, map[string]any{"cmd": []any{"true"}, "cwd": "/definitely/not/here"})
	if code := errorCode(t, r); code != "bad_request" {
		t.Fatalf("code = %q", code)
	}
	rec.none(t)
}

// A cwd the broker cannot stat is handed to the executor anyway: the executor's
// uid enters the directory and can hold traversal the broker does not, which is
// the ordinary state of a tree under an ecryptfs home.
func TestACwdTheBrokerCannotStatIsLeftToTheExecutor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses regardless, so there is no EACCES to produce")
	}
	s, rec := execServer(t)
	// 0000 on the parent, so stat is EACCES rather than ENOENT.
	sealed := filepath.Join(t.TempDir(), "sealed")
	inside := filepath.Join(sealed, "tree")
	if err := os.MkdirAll(inside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(sealed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(sealed, 0o755) })
	if _, err := os.Stat(inside); !os.IsPermission(err) {
		t.Fatalf("setup did not produce EACCES: %v", err)
	}

	r := exec(t, s, map[string]any{"cmd": []any{"true"}, "cwd": inside})
	if _, refused := r["error"]; refused {
		t.Fatalf("refused a cwd the executor could have reached: %v", r["error"])
	}
	if got := rec.only(t).Cwd; got != inside {
		t.Errorf("cwd = %q, want %q", got, inside)
	}
}

// -- the concurrency limit --------------------------------------------------

// Refused rather than queued.  max_concurrency is 2 in the test config, so the
// third request in flight is the one told.
func TestOverTheConcurrencyLimitIsRefusedAsBusy(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})

	release := make(chan struct{})
	entered := make(chan struct{}, 8)
	s.exec = func(r *redact.Redactor, sink func(string), req executor.Request) (*executor.Result, error) {
		entered <- struct{}{}
		<-release
		return &executor.Result{ExitCode: 0}, nil
	}

	var wg sync.WaitGroup
	for range s.Config.Command.Concurrency {
		wg.Go(func() {
			exec(t, s, map[string]any{"cmd": []any{"true"}})
		})
	}
	// Both slots are held before the next request is made.
	for range s.Config.Command.Concurrency {
		<-entered
	}

	// On a deadline: the failure mode is a request that queues, which would
	// otherwise block here forever.
	over := make(chan protocol.Response, 1)
	go func() { over <- exec(t, s, map[string]any{"cmd": []any{"true"}}) }()
	select {
	case r := <-over:
		if code := errorCode(t, r); code != "busy" {
			t.Errorf("code = %q, want busy", code)
		}
	case <-time.After(10 * time.Second):
		close(release)
		wg.Wait()
		t.Fatal("a request over the limit was queued instead of refused")
	}

	close(release)
	wg.Wait()

	// And the slot is returned, so the next request is served.
	if r := exec(t, s, map[string]any{"cmd": []any{"true"}}); r["error"] != nil {
		t.Errorf("a slot was not released: %v", r["error"])
	}
}

// -- the audit record -------------------------------------------------------

func lastRecord(t *testing.T, s *Server) map[string]any {
	t.Helper()
	data, err := os.ReadFile(s.Config.Audit.LogPath)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	var record map[string]any
	if err := json.Unmarshal([]byte(lines[len(lines)-1]), &record); err != nil {
		t.Fatalf("record is not JSON: %v", err)
	}
	return record
}

// The record names who, what, where and which refs, and carries no value.
func TestTheAuditRecordNamesEverythingButTheValues(t *testing.T) {
	s, rec := execServer(t)
	rec.output = "connecting with " + goodValue + "\n"
	r := exec(t, s, map[string]any{
		"cmd":      []any{"true", "--password=" + goodValue},
		"env_refs": map[string]any{"ROUTER_PW": "faramir://a/b"},
	})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	record := lastRecord(t, s)

	body, err := json.Marshal(record)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(body), goodValue) {
		t.Errorf("PLAINTEXT IN THE RECORD: %s", body)
	}

	token := redact.TokenFor("a/b")
	if out, _ := record["output"].(string); !strings.Contains(out, token) {
		t.Errorf("output was not recorded tokenized: %q", out)
	}
	// Legible, which is the point of redacting rather than dropping it.
	cmd, err := json.Marshal(record["cmd"])
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(cmd), "--password="+token) {
		t.Errorf("the command line was not recorded legibly: %s", cmd)
	}
	// env_refs are names, never values.
	refs, _ := record["env_refs"].(map[string]any)
	if refs["ROUTER_PW"] != "a/b" {
		t.Errorf("env_refs = %v", refs)
	}
	peer, _ := record["peer"].(map[string]any)
	if peer["uid"] != float64(1000) {
		t.Errorf("the peer was not recorded: %v", peer)
	}
	for _, key := range []string{"log_id", "exit_code", "cwd", "argv0_path", "started_at"} {
		if _, ok := record[key]; !ok {
			t.Errorf("the record has no %s", key)
		}
	}
}

// A command that never started is still recorded.
func TestAResolveFailureIsRecordedAndReported(t *testing.T) {
	s, _ := execServer(t)
	r := exec(t, s, map[string]any{"cmd": []any{"definitely-not-installed-xyzzy"}})

	if code := errorCode(t, r); code != "exec_failed" {
		t.Fatalf("code = %q", code)
	}
	msg := errorMessage(t, r)
	// The failure an operator actually hits, so it says what to do.
	for _, want := range []string{"not found on the broker's PATH", "env"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q: %q", want, msg)
		}
	}
	if record := lastRecord(t, s); record["error"] == nil {
		t.Errorf("the refusal was not recorded: %v", record)
	}
}

// -- the response -----------------------------------------------------------

// The counts are how a caller confirms a value landed without seeing it.
func TestTheResponseReportsRedactionCountsAndTheLogID(t *testing.T) {
	s, rec := execServer(t)
	rec.output = goodValue + " and again " + goodValue + "\n"
	r := exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "faramir://a/b"},
	})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	if out, _ := r["output"].(string); strings.Contains(out, goodValue) {
		t.Errorf("PLAINTEXT LEAKED: %q", out)
	}
	counts, _ := r["redactions"].([]redact.Count)
	if len(counts) != 1 || counts[0].Count != 2 {
		t.Fatalf("redactions = %+v, want one token counted twice", counts)
	}
	if id, _ := r["log_id"].(string); id == "" {
		t.Error("no log_id to quote to the operator")
	}
}

// exec_failed, with the message through the redactor.
func TestAnExecutorFailureIsRedactedBeforeItIsReported(t *testing.T) {
	s, rec := execServer(t)
	rec.err = &executorError{"connecting to " + goodValue + " failed"}
	r := exec(t, s, map[string]any{"cmd": []any{"true"}})

	if code := errorCode(t, r); code != "exec_failed" {
		t.Fatalf("code = %q", code)
	}
	msg := errorMessage(t, r)
	if strings.Contains(msg, goodValue) {
		t.Errorf("PLAINTEXT LEAKED through an error: %q", msg)
	}
	if !strings.Contains(msg, redact.TokenFor("a/b")) {
		t.Errorf("the error was not redacted: %q", msg)
	}
}

type executorError struct{ msg string }

func (e *executorError) Error() string { return e.msg }

// An exec is a pair of records sharing one log_id, and the first is written
// before the child runs.  Without it a command is absent from the log for as
// long as it takes, so `faramir logs --watch` shows a playbook only once it is
// over and a run that never returns leaves nothing behind at all.
func TestAnExecIsRecordedWhenItStartsAndWhenItEnds(t *testing.T) {
	s, _ := execServer(t)
	response := exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	logID, _ := response["log_id"].(string)
	if logID == "" {
		t.Fatal("the exec was answered without a log_id")
	}

	var started, ended map[string]any
	for _, record := range records(t, s) {
		if str(record, "log_id") != logID {
			continue
		}
		switch str(record, "op") {
		case "exec_started":
			started = record
		case "exec":
			ended = record
		}
	}
	if started == nil {
		t.Fatal("nothing was recorded when the command started")
	}
	if ended == nil {
		t.Fatal("nothing was recorded when the command ended")
	}
	// The start record names the command, which is the whole of what it is for: a
	// row saying only that something is running answers nothing.
	if cmd, _ := started["cmd"].([]any); len(cmd) == 0 {
		t.Errorf("the start record names no command: %v", started)
	}
	// And carries no outcome, there being none yet.  A zero exit code here would
	// read as a command that finished cleanly the moment it began.
	if _, ok := started["exit_code"]; ok {
		t.Errorf("the start record carries an exit code: %v", started["exit_code"])
	}
	if _, ok := ended["exit_code"]; !ok {
		t.Errorf("the end record carries no exit code: %v", ended)
	}
}

// str reads a string field, absent reading as empty.
func str(record map[string]any, key string) string {
	value, _ := record[key].(string)
	return value
}
