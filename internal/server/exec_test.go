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

// These cover what the broker decides around a child process, which is the
// bulk of what it does: the timeout it settles on, the environment it
// assembles, the record it writes, the limit it enforces.  None of it needs a
// socket, a PTY or a forked process, and reaching it through those tested the
// plumbing rather than the decision.

// recorder stands in for the executor.  It captures the request and returns a
// canned result, so the assertions are about what the broker handed over.
//
// Env is snapshotted, because the broker wipes the map it assembled once the
// child holds the values: a test that read it afterwards would see an empty
// one and conclude nothing was injected.  liveEnv keeps the original map so
// that wiping can be asserted on directly.
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
		// Through the real redactor, and into both the result and the sink,
		// because that is what the real executor does: the response and the
		// audit log are the same redacted text, capped differently.  Feeding
		// only the sink would leave every assertion about the response body
		// unable to fail.
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

// none asserts the executor was never reached, which is what "refused before
// anything ran" means: a refusal that still forked a child has refused nothing.
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

// A directory is filled in unless the test named one.  The broker refuses a
// request that carries none, so without this every test here would be
// exercising that refusal instead of what it is about.
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

// A request that names no timeout gets the configured default, and one that
// asks for more than max_timeout_sec is clamped rather than refused.  Neither
// had any coverage: the clamp is the only thing bounding how long a brokered
// command can hold a concurrency slot.
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
			if tc.asked != nil {
				request["timeout_sec"] = float64(tc.asked.(int))
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

// The broker assembles base_env plus exactly the refs that were asked for.
// HOME is deliberately absent from what it hands over: it belongs to the
// executor's uid, not the broker's, and the executor supplies it.
//
// Note the scope.  This is the map the broker builds, not the environment the
// child ends up with, so it cannot say anything about key material reaching a
// child: the broker has no key to leak, and asserting that it does not add a
// variable it has no way to populate would pass whatever the code did.  That
// property is asserted against a real child in internal/e2e.
func TestTheEnvironmentTheBrokerAssembles(t *testing.T) {
	s, rec := execServer(t)
	r := exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://a/b"},
	})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	env := rec.only(t).Env

	if env["PATH"] != "/usr/bin:/bin" {
		t.Errorf("PATH = %q; base_env did not reach the child", env["PATH"])
	}
	if env["ROUTER_PW"] != goodValue {
		t.Errorf("the ref was not injected: %q", env["ROUTER_PW"])
	}
	if _, ok := env["HOME"]; ok {
		t.Error("HOME was set by the broker; it belongs to the executor's uid")
	}
	// Nothing beyond base_env and the refs: an extra variable here is one the
	// caller did not ask for and the operator did not configure.
	if len(env) != len(s.Config.Exec.BaseEnv)+1 {
		t.Errorf("environment = %v, want base_env plus ROUTER_PW only", env)
	}
}

// The map the values were assembled in is wiped once the child holds them, so
// a plaintext copy does not outlive the request in the broker's heap.  The
// store keeps the values, which is where they belong.
func TestTheAssembledEnvironmentIsWipedAfterTheRun(t *testing.T) {
	s, rec := execServer(t)
	exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://a/b"},
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
		{"unknown", "secret://nope", "unknown secret ref"},
		{"refused at load", "secret://tiny", "refused at load"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s, _ := execServer(t)
			r := exec(t, s, map[string]any{
				"cmd": []any{"true"}, "env_refs": map[string]any{"X": tc.uri},
			})
			if code := errorCode(t, r); code != "unknown_secret" {
				t.Fatalf("code = %q", code)
			}
			msg := r["error"].(map[string]string)["message"]
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
		"cmd": []any{"true"}, "env_refs": map[string]any{"X": "secret://nope"},
	})
	rec.none(t)
}

// -- cwd --------------------------------------------------------------------

// There is nothing to default to.  A brokered command runs where its caller
// was, and the config names no directory to fall back on, so a request that
// omits one is refused rather than relocated somewhere nobody asked for.
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

// A cwd the broker's own uid cannot stat is handed to the executor anyway.
// The executor is the uid that enters the directory and can hold traversal the
// broker does not, which is the ordinary state of a tree under an ecryptfs home:
// that filesystem takes one ACL and silently drops later edits, so an executor
// grant made before the broker needed one cannot be extended afterwards.
// Refusing here would make that arrangement permanently unusable.
func TestACwdTheBrokerCannotStatIsLeftToTheExecutor(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses regardless, so there is no EACCES to produce")
	}
	s, rec := execServer(t)
	// 0000 on the parent: the child path is real, and stat on it is EACCES
	// rather than ENOENT.
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

// Over the limit the broker refuses with a clear error rather than queueing.
// max_concurrency is 2 in the test config, so the third request in flight is
// the one that has to be told.
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
	for range s.Config.Server.MaxConcurrency {
		wg.Add(1)
		go func() {
			defer wg.Done()
			exec(t, s, map[string]any{"cmd": []any{"true"}})
		}()
	}
	// Both slots are held before the next request is made.
	for range s.Config.Server.MaxConcurrency {
		<-entered
	}

	// On a deadline, because the failure mode is a request that queues rather
	// than one that returns the wrong code: without this the test would block
	// here forever and report a timeout instead of a reason.
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
		"env_refs": map[string]any{"ROUTER_PW": "secret://a/b"},
	})
	if r["error"] != nil {
		t.Fatalf("error: %v", r["error"])
	}
	record := lastRecord(t, s)

	body, _ := json.Marshal(record)
	if strings.Contains(string(body), goodValue) {
		t.Errorf("PLAINTEXT IN THE RECORD: %s", body)
	}

	token := redact.TokenFor("a/b")
	if out, _ := record["output"].(string); !strings.Contains(out, token) {
		t.Errorf("output was not recorded tokenized: %q", out)
	}
	// The command line stays legible, which is the point of redacting it
	// rather than dropping it.
	cmd, _ := json.Marshal(record["cmd"])
	if !strings.Contains(string(cmd), "--password="+token) {
		t.Errorf("the command line was not recorded legibly: %s", cmd)
	}
	// env_refs are names, never values, and they are what makes the record
	// useful without one.
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

// A command that never started is still recorded: "it was refused" is the
// thing an operator most needs the log to say.
func TestAResolveFailureIsRecordedAndReported(t *testing.T) {
	s, _ := execServer(t)
	r := exec(t, s, map[string]any{"cmd": []any{"definitely-not-installed-xyzzy"}})

	if code := errorCode(t, r); code != "exec_failed" {
		t.Fatalf("code = %q", code)
	}
	msg := r["error"].(map[string]string)["message"]
	// The one failure an operator actually hits, so it has to be
	// self-correcting rather than merely true.
	for _, want := range []string{"not found on the broker's PATH", "base_env"} {
		if !strings.Contains(msg, want) {
			t.Errorf("message does not mention %q: %q", want, msg)
		}
	}
	if record := lastRecord(t, s); record["error"] == nil {
		t.Errorf("the refusal was not recorded: %v", record)
	}
}

// -- the response -----------------------------------------------------------

// The counts are how a caller confirms a credential landed without seeing it,
// so they have to survive the trip out.
func TestTheResponseReportsRedactionCountsAndTheLogID(t *testing.T) {
	s, rec := execServer(t)
	rec.output = goodValue + " and again " + goodValue + "\n"
	r := exec(t, s, map[string]any{
		"cmd":      []any{"true"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://a/b"},
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

// An executor that fails is reported as exec_failed, and its message goes
// through the redactor: an unexpected error can have interpolated a value.
func TestAnExecutorFailureIsRedactedBeforeItIsReported(t *testing.T) {
	s, rec := execServer(t)
	rec.err = &executorError{"connecting to " + goodValue + " failed"}
	r := exec(t, s, map[string]any{"cmd": []any{"true"}})

	if code := errorCode(t, r); code != "exec_failed" {
		t.Fatalf("code = %q", code)
	}
	msg := r["error"].(map[string]string)["message"]
	if strings.Contains(msg, goodValue) {
		t.Errorf("PLAINTEXT LEAKED through an error: %q", msg)
	}
	if !strings.Contains(msg, redact.TokenFor("a/b")) {
		t.Errorf("the error was not redacted: %q", msg)
	}
}

type executorError struct{ msg string }

func (e *executorError) Error() string { return e.msg }
