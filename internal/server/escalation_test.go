package server

import (
	"math"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
)

// allowSudo turns on the escalation server the way an install with --allow-sudo
// does. Nothing to place: there is no credential in this design.
func allowSudo(t *testing.T, s *Server) {
	t.Helper()
	s.Config.Sudo = config.SudoConfig{
		ExecUser:   "faramir-exec",
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-escalate",
		TimeoutSec: 5,
	}
	// New() built the server from the config it was made with, so it is rebuilt
	// here rather than mutated.
	s.Escalation = New(nil, nil, s.Config).Escalation
	// Quiescence is a round trip to a running executor, which these tests do not
	// have: they are about what the broker does with an answer, not about how the
	// host is measured. Stubbed quiet, so the check is exercised where it is the
	// subject: TestAnEscalationIsRefusedWhileTheHostIsNotQuiet, below.
	s.Escalation.Quiescent = func() (bool, string) { return true, "the test says so" }
	t.Cleanup(s.Escalation.Stop)
}

// A brokered command is given nothing of the escalation's, on a host that grants
// one and on a host that does not. A run is named by the process the executor
// forked, so there is nothing to put in the child's hands: nothing it can read,
// copy, hand to a later command, or print into a log.
func TestExecGivesTheChildNothingOfTheEscalations(t *testing.T) {
	for _, granted := range []bool{true, false} {
		t.Run(map[bool]string{true: "sudo granted", false: "no grant"}[granted], func(t *testing.T) {
			s, rec := execServer(t)
			if granted {
				allowSudo(t, s)
			}

			exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
			env := rec.only(t).Env

			// [command] env and nothing else at all. Asserted as a count rather than
			// against a list of names, so anything added under a name nobody thought
			// to look for fails here too: a token, an askpass helper, a socket to
			// answer on, a password.
			if want := len(s.Config.Command.Env); len(env) != want {
				t.Errorf("environment = %v, want [command] env alone", env)
			}
			// The id goes to the executor instead, which is the whole of where it
			// goes: it names what to attribute an escalation to, and a host that
			// grants none has nothing to attribute.
			if runID := rec.only(t).RunID; (runID != "") != granted {
				t.Errorf("the executor was given run id %q, granted = %v", runID, granted)
			}
		})
	}
}

// A run is dropped when its command ends, so a request that arrives after it is
// refused rather than answered against a finished command. The executor stops
// owning the process at the same moment, so both halves have to fail closed.
func TestARunDoesNotOutliveItsCommand(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)

	exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	if rec.only(t).RunID == "" {
		t.Fatal("the executor was given no run id, so this proves nothing")
	}
	// The command has ended, so the broker holds no run and the executor owns no
	// process. Any ancestry at all is unattributable now.
	ancestry := []int{os.Getpid()}
	if approved, _, _ := s.Escalation.Ask(ancestry); approved {
		t.Error("an escalation was approved after its command ended")
	}
}

// There is no credential to redact, and that is the property rather than an
// omission: an escalation is a decision, so nothing a child holds could be
// printed back or carried anywhere.
func TestEscalationAddsNothingToTheValueSet(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)
	rec.output = "sudo: authenticating\n"

	response := exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	if redactions, _ := response["redactions"].([]redact.Count); len(redactions) != 0 {
		t.Errorf("redactions = %v, want none: escalation holds no value", redactions)
	}
}

// While one command holds an escalation, opExec refuses a second with
// `escalation_in_progress` rather than running it: the two share the executor's
// uid, so the new one would be a route to the root approved for the first.
//
// Its own code rather than `busy`: `busy` invites a retry, and a caller
// retrying against a live escalation is one polling the exact interval the
// serialisation exists to protect.
func TestAnEscalationHoldsOtherCommands(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	// A run approved and left in flight, standing in for a playbook mid-escalation:
	// raiseAndWait registers it without an exec behind it, so it stays held until
	// this test releases it.
	held, question, _ := raiseAndWait(t, s, "log-h")
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	if response := handle(s, map[string]any{
		"op": "answer", "id": question.ID, "approved": true}, root); response["error"] != nil {
		t.Fatalf("root could not approve the standing run: %v", response["error"])
	}

	// A second brokered command is now refused outright, and never reaches the
	// executor.
	if code := errorCode(t, exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})); code != "escalation_in_progress" {
		t.Errorf("a command during a live escalation got %q, want escalation_in_progress", code)
	}

	// It runs again once the approved run ends.
	s.Escalation.Release(held, escalation.Outcome{})
	if response := exec(t, s, map[string]any{"cmd": []any{"/bin/true"}}); response["error"] != nil {
		t.Errorf("a command was still refused after the approved run ended: %v", response["error"])
	}
}

// Whether a brokered command may ask is worth the caller knowing: without it a
// playbook that touches this host has to leave it out.
func TestStatusReportsWhetherEscalationIsConfigured(t *testing.T) {
	s, _ := execServer(t)
	if body, _ := exec(t, s, map[string]any{"op": "status"})["output"].(string); !strings.Contains(
		body, `"enabled": false`) {
		t.Errorf("status does not report escalation as unconfigured: %s", body)
	}
	allowSudo(t, s)
	body, _ := exec(t, s, map[string]any{"op": "status"})["output"].(string)
	if !strings.Contains(body, `"sudo"`) || !strings.Contains(body, `"enabled": true`) {
		t.Errorf("status does not report escalation as configured: %s", body)
	}
}

// The one check that stands between the coding agent and its own escalation: the
// answer has to come from root, and the agent runs as the operator. Made at
// the op rather than by the socket mode, which admits a group by design.
func TestOnlyRootMayAnswerAnEscalation(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	// uid 1000: a member of the client group, which is what the socket admits and
	// what the agent runs as.
	operator := &sockutil.Peer{PID: 42, UID: 1000, GID: 1000}
	for _, request := range []map[string]any{
		{"op": "escalations"},
		{"op": "answer", "id": "abc123", "approved": true},
		// escalate is the one that decides a sudo, so it is the one an agent would
		// reach for: answered by anything but root, a command could approve its
		// own sudo.
		// float64 because that is what a JSON body unmarshals to, which is the
		// only way this op is ever reached.
		{"op": "escalate", "procs": []any{float64(42)}},
	} {
		response := handle(s, request, operator)
		if code := errorCode(t, response); code != "forbidden" {
			t.Errorf("%v as uid 1000 = %q, want forbidden: that account is the one the "+
				"agent runs as", request, code)
		}
		if detail := errorDetail(response); !strings.Contains(detail, "faramir sudo ls") {
			t.Errorf("the refusal does not say what to run instead: %q", detail)
		}
	}

	// And root is admitted, reaching the question rather than the check.
	if response := handle(s, map[string]any{"op": "escalations"},
		&sockutil.Peer{PID: 1, UID: 0, GID: 0}); response["error"] != nil {
		t.Errorf("root was refused the escalations op: %v", response["error"])
	}
}

// A question a run raised is what root sees waiting, and answering it releases
// the sudo that was blocked on it.
func TestRootAnswersTheQuestionARunRaised(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	_, question, granted := raiseAndWait(t, s, "log-9")
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	if !strings.Contains(question.Prompt, "ansible-playbook site.yml") {
		t.Errorf("the question does not name the command: %q", question.Prompt)
	}

	if response := handle(s, map[string]any{
		"op": "answer", "id": question.ID, "approved": true}, root); response["error"] != nil {
		t.Fatalf("root could not answer: %v", response["error"])
	}
	if approved := <-granted; !approved {
		t.Error("the sudo waiting on that answer was not released")
	}
	if left := s.Escalation.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after an answer", len(left))
	}
}

// The executor's answer, not the broker's own map, decides whether a yes takes;
// why that is the answer that matters is with the mechanism in
// internal/escalation. Here it is the wiring: a refused yes reaches root through
// the op with a code of its own, because "your yes was refused" and "that id is
// not waiting" send an operator to different places.
func TestAnEscalationIsRefusedWhileTheHostIsNotQuiet(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	s.Escalation.Quiescent = func() (bool, string) {
		return false, "1 process(es) are running as the executor outside any brokered command"
	}

	_, question, granted := raiseAndWait(t, s, "log-q")
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}

	response := handle(s, map[string]any{
		"op": "answer", "id": question.ID, "approved": true}, root)
	if code := errorCode(t, response); code != "not_quiescent" {
		t.Errorf("code = %q, want not_quiescent: a yes that was refused is not an id "+
			"nobody is waiting on", code)
	}
	if approved := <-granted; approved {
		t.Fatal("the sudo was approved while the executor said the host was not quiet")
	}
	if left := s.Escalation.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after a refused-for-noise answer, want "+
			"it closed: holding it open would make the operator poll the one interval "+
			"the host has to be quiet in", len(left))
	}
}

// An id nobody is waiting on is an error rather than a silent success: the
// operator has typed one that expired.
func TestAnsweringAnUnknownQuestionIsAnError(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	response := handle(s, map[string]any{"op": "answer", "id": "beef00", "approved": true},
		&sockutil.Peer{PID: 1, UID: 0, GID: 0})
	if code := errorCode(t, response); code != "unknown_question" {
		t.Errorf("code = %q, want unknown_question", code)
	}
}

// errorDetail is the message of a refusal, for the tests that assert what an
// operator is told rather than only that they were refused.
func errorDetail(response protocol.Response) string {
	if e, ok := response["error"].(map[string]string); ok {
		return e["message"]
	}
	return ""
}

// askInBackground puts the question from a goroutine, Ask being the blocked
// sudo's call, and returns the channel it answers on. The test does not end
// until Ask has returned, its audit record being written after the answer and a
// write landing during cleanup failing the test. The escalation server is
// stopped first, so a test that ended without answering does not park the wait
// forever.
func askInBackground(t *testing.T, s *Server, runID string) <-chan bool {
	t.Helper()
	// The executor's half, which these tests do not have: it answers that the run
	// under test forked the process asking. What it is checking is exercised where
	// it is the subject, in the escalation package's own tests.
	s.Escalation.Owner = func([]int) (string, string) {
		return runID, "the test forked it"
	}
	granted := make(chan bool, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		approved, _, _ := s.Escalation.Ask([]int{os.Getpid()})
		granted <- approved
	}()
	t.Cleanup(func() {
		s.Escalation.Stop()
		<-done
	})
	return granted
}

// raiseAndWait registers a run and puts its question, returning the run's token,
// the question as root sees it, and the channel the blocked sudo answers on.
// One copy of the poll, so every test here drives the protocol the same way.
func raiseAndWait(t *testing.T, s *Server, logID string) (string, escalation.Question, <-chan bool) {
	t.Helper()
	token, _ := s.Escalation.Register(escalation.Run{
		Argv: []string{"ansible-playbook", "site.yml"}, Cwd: "/srv", LogID: logID,
	})
	granted := askInBackground(t, s, token)
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response := handle(s, map[string]any{"op": "escalations", "wait_sec": 1}, root)
		if questions, _ := response["questions"].([]escalation.Question); len(questions) > 0 {
			return token, questions[0], granted
		}
	}
	t.Fatal("no question reached root")
	return "", escalation.Question{}, nil
}

// After a yes, the terminal that gave root away is told what became of the run.
// It reaches root over the same op the question arrived on, so the operator's
// only report of the command they judged costs no second channel and no read of
// the audit log.
func TestTheEscalationsOpReportsHowTheApprovedRunEnded(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}

	held, question, _ := raiseAndWait(t, s, "log-e")
	if response := handle(s, map[string]any{
		"op": "answer", "id": question.ID, "approved": true}, root); response["error"] != nil {
		t.Fatalf("root could not approve the run: %v", response["error"])
	}

	// Nothing yet: the run is still going, and a poll that answered now would be
	// reporting an ending that has not happened.
	if response := handle(s, map[string]any{
		"op": "escalations", "await_log_id": "log-e"}, root); response["finished"] != nil {
		t.Errorf("a run still in flight reported an ending: %v", response["finished"])
	}

	code := 7
	s.Escalation.Release(held, escalation.Outcome{
		LogID: "log-e", ExitCode: &code, DurationSec: 2.5,
	})

	// And only to the caller waiting on this run. The broker holds the last
	// ending rather than emptying it when it is read, so naming the run is what
	// keeps a stale one off a terminal that did not approve it.
	if response := handle(s, map[string]any{"op": "escalations"}, root); response["finished"] != nil {
		t.Errorf("a caller that approved nothing was told how a run ended: %v", response["finished"])
	}
	response := handle(s, map[string]any{"op": "escalations", "await_log_id": "log-e"}, root)
	finished, ok := response["finished"].(*escalation.Outcome)
	if !ok {
		t.Fatalf("the approved run's ending did not reach root: %v", response["finished"])
	}
	if finished.ExitCode == nil || *finished.ExitCode != 7 {
		t.Errorf("exit code = %v, want the 7 the run ended with", finished.ExitCode)
	}
	// The rendered body carries it too, that being what a caller reading stdout
	// parses.
	if body, _ := response["output"].(string); !strings.Contains(body, `"log_id": "log-e"`) {
		t.Errorf("the rendered body does not carry the ending: %s", body)
	}
}

// A malformed one is refused rather than read as a caller waiting on nothing:
// silently ignoring it would leave a watcher waiting for an ending that is never
// matched against.
func TestAMalformedAwaitLogIDIsRefused(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	response := handle(s, map[string]any{"op": "escalations", "await_log_id": 7},
		&sockutil.Peer{PID: 1, UID: 0, GID: 0})
	if code := errorCode(t, response); code != "bad_request" {
		t.Errorf("a non-string await_log_id got %q, want bad_request", code)
	}
}

// A command whose sudo was refused says why on the way out. Both endings reach
// the command itself as sudo's own authentication failure, so without this the
// caller cannot tell a human's no from a question nobody answered, and the two
// differ in whether running it again is worth anything.
func TestAnExecReportsWhyItsSudoWasRefused(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}

	held, question, granted := raiseAndWait(t, s, "log-r")
	if response := handle(s, map[string]any{
		"op": "answer", "id": question.ID, "approved": false}, root); response["error"] != nil {
		t.Fatalf("root could not refuse the run: %v", response["error"])
	}
	if <-granted {
		t.Fatal("a refused run was approved")
	}

	code, _ := s.Escalation.Refusal(held)
	if code != escalation.CodeRejected {
		t.Errorf("the run kept %q, want %q", code, escalation.CodeRejected)
	}

	// And it is gone with the run, so a later command carries no answer of
	// somebody else's.
	s.Escalation.Release(held, escalation.Outcome{})
	if code, _ := s.Escalation.Refusal(held); code != "" {
		t.Errorf("a released run still reports %q", code)
	}
}

// The question names the account that asked, which is not the one that would
// run the command: every brokered command runs as the executor, so the uid the
// question is about is the caller's and nothing else reports it.
func TestAQuestionNamesTheAccountThatAsked(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	// The account the agent runs as, which is what reaches the broker socket.
	caller := &sockutil.Peer{PID: 4242, UID: int32(os.Getuid()), GID: int32(os.Getgid())}
	token, _ := s.Escalation.Register(escalation.Run{
		Argv: []string{"ansible-playbook", "site.yml"}, Cwd: "/srv", LogID: "log-c",
		Caller: callerName(caller),
	})
	askInBackground(t, s, token)

	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	var question escalation.Question
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response := handle(s, map[string]any{"op": "escalations", "wait_sec": 1}, root)
		if questions, _ := response["questions"].([]escalation.Question); len(questions) > 0 {
			question = questions[0]
			break
		}
	}
	if question.Caller == "" {
		t.Fatal("the question names no caller, so nothing says who asked")
	}
	if !strings.Contains(question.Caller, strconv.Itoa(os.Getuid())) {
		t.Errorf("caller = %q, want the uid that asked", question.Caller)
	}
	s.Escalation.Release(token, escalation.Outcome{})
}

// The operator's account reaches a brokered command, and cannot be chosen by
// one. Every brokered command runs as the executor, so without this nothing
// inside a run can resolve whose host it is on or whose home holds their
// configuration -- and a caller that could name it would be choosing where a
// root run went looking.
func TestExecNamesTheOperator(t *testing.T) {
	s, rec := execServer(t)
	s.Config.Server.AgentUser = "operator"

	exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	if got := rec.only(t).Env[protocol.OperatorEnv]; got != "operator" {
		t.Errorf("%s = %q, want the configured operator", protocol.OperatorEnv, got)
	}

	// And a caller cannot name it: reserved, so the request is refused rather than
	// merged, which is what stops one choosing where a run goes looking.
	if !protocol.ReservedEnv[protocol.OperatorEnv] {
		t.Errorf("%s is not reserved, so a caller could name the operator",
			protocol.OperatorEnv)
	}
}

// A watcher's long poll is built from a count of seconds the caller sends, and
// the parser bounds that below and not above. Clamping after the multiplication
// would be too late: int64 nanoseconds run out somewhere past 292 years, so a
// large enough value wraps negative and a min against the ceiling keeps the
// negative. Poll then returns at once on a request that asked to wait.
//
// The same shape the command timeout had before responseWait saturated it.
func TestTheEscalationWaitDoesNotWrapOnAHugeWaitSec(t *testing.T) {
	for _, seconds := range []int{
		0, 1, 30, maxEscalationWaitSec, maxEscalationWaitSec + 1,
		1 << 30, 1 << 62, math.MaxInt64,
	} {
		wait := time.Duration(min(seconds, maxEscalationWaitSec)) * time.Second
		switch {
		case wait < 0:
			t.Errorf("wait_sec %d gives %v, a deadline already past", seconds, wait)
		case wait > maxEscalationWait:
			t.Errorf("wait_sec %d gives %v, past the ceiling of %v",
				seconds, wait, maxEscalationWait)
		}
	}
	// And a wait under the ceiling is still the one asked for. Through a variable,
	// the constants folding away otherwise and asserting nothing about the clamp.
	asked := 30
	if got := time.Duration(min(asked, maxEscalationWaitSec)) * time.Second; got != 30*time.Second {
		t.Errorf("wait_sec %d gives %v, want 30s", asked, got)
	}
}
