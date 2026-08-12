package server

import (
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/approval"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
)

// allowSudo turns on the approval server the way an install with --allow-sudo
// does.  Nothing to place: there is no credential in this design.
func allowSudo(t *testing.T, s *Server) {
	t.Helper()
	s.Config.Sudo = config.SudoConfig{
		ExecUser:   "faramir-exec",
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-approve",
		TimeoutSec: 5,
	}
	// New() built the server from the config it was made with, so it is rebuilt
	// here rather than mutated.
	s.Approval = New(s.Config).Approval
	// Quiescence is a round trip to a running executor, which these tests do not
	// have: they are about what the broker does with an answer, not about how the
	// host is measured.  Stubbed quiet, so the check is exercised where it is the
	// subject: TestAnApprovalIsRefusedWhileTheHostIsNotQuiet, below.
	s.Approval.Quiescent = func() (bool, string) { return true, "the test says so" }
	t.Cleanup(s.Approval.Stop)
}

// A brokered command is given a token and nothing else.  It names the run so a
// question can name the command; it authorises nothing, the op that spends it
// being refused to anything but root.
func TestExecInjectsTheToken(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)

	exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	env := rec.only(t).Env

	if env[approval.TokenEnv] == "" {
		t.Errorf("%s is unset, so a question could name no command", approval.TokenEnv)
	}
	// Nothing that was ever a credential: no askpass helper, no socket, no
	// password.  A child that finds one of these has something it can keep.
	for _, gone := range []string{"SUDO_ASKPASS", "FARAMIR_ASKPASS_SOCKET", "FARAMIR_ASKPASS_TOKEN"} {
		if value, set := env[gone]; set {
			t.Errorf("%s = %q: this design hands the child no credential", gone, value)
		}
	}
}

// Without an install that asked for approval, nothing is injected and sudo
// fails the way it does on any host that granted nothing.
func TestExecInjectsNothingWithoutASudoGrant(t *testing.T) {
	s, rec := execServer(t)
	exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	if value, set := rec.only(t).Env[approval.TokenEnv]; set {
		t.Errorf("%s = %q on a host that granted no sudoers entry", approval.TokenEnv, value)
	}
}

// The token is dropped when the command ends, so a request that arrives after
// it names nothing and is refused rather than answered against a finished
// command.
func TestTheTokenDoesNotOutliveTheCommand(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)

	exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	token := rec.only(t).Env[approval.TokenEnv]
	if token == "" {
		t.Fatal("no token was injected")
	}
	if approved, _ := s.Approval.Ask(token); approved {
		t.Error("a token was approved after its command ended")
	}
}

// There is no credential to redact, and that is the property rather than an
// omission: an approval is a decision, so nothing a child holds could be
// printed back or carried anywhere.
func TestApprovalAddsNothingToTheValueSet(t *testing.T) {
	s, rec := execServer(t)
	allowSudo(t, s)
	rec.output = "sudo: authenticating\n"

	response := exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})
	if redactions, _ := response["redactions"].([]redact.Count); len(redactions) != 0 {
		t.Errorf("redactions = %v, want none: approval holds no value", redactions)
	}
}

// While one command holds an approval, opExec refuses a second with
// `approval_in_progress` rather than running it: the two share the executor's
// uid, so the new one would be a route to the root approved for the first.  This
// is the wiring of the serialization the approval server enforces, checked
// through real dispatch.
//
// Its own code rather than `busy`, and the difference is the point: `busy`
// invites a retry, and a caller retrying against a live approval is one polling
// the exact interval the serialization exists to protect.  The code names the
// host's state rather than the request's, so nothing in it can be read as this
// command having been queued.
func TestAnApprovalHoldsOtherCommands(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	// A run approved and left in flight, standing in for a playbook mid-approval:
	// registered directly so it does not release the moment its command exits.
	held, _ := s.Approval.Register(approval.Run{
		Argv: []string{"ansible-playbook", "site.yml"}, Cwd: "/srv", LogID: "log-h",
	})
	go s.Approval.Ask(held)
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	var id string
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline) && id == ""; {
		response := s.Handle(map[string]any{"op": "approvals", "wait_sec": 1}, root)
		if questions, _ := response["questions"].([]approval.Question); len(questions) > 0 {
			id = questions[0].ID
		}
	}
	if response := s.Handle(map[string]any{"op": "approve", "id": id, "approve": true}, root); response["error"] != nil {
		t.Fatalf("root could not approve the standing run: %v", response["error"])
	}

	// A second brokered command is now refused outright, and never reaches the
	// executor.
	if code := errorCode(t, exec(t, s, map[string]any{"cmd": []any{"/bin/true"}})); code != "approval_in_progress" {
		t.Errorf("a command during a live approval got %q, want approval_in_progress", code)
	}

	// It runs again once the approved run ends.
	s.Approval.Release(held)
	if response := exec(t, s, map[string]any{"cmd": []any{"/bin/true"}}); response["error"] != nil {
		t.Errorf("a command was still refused after the approved run ended: %v", response["error"])
	}
}

// Whether a brokered command may ask is worth the caller knowing: without it a
// playbook that touches this host has to leave it out.
func TestStatusReportsWhetherApprovalIsConfigured(t *testing.T) {
	s, _ := execServer(t)
	if body, _ := exec(t, s, map[string]any{"op": "status"})["output"].(string); !strings.Contains(
		body, `"enabled": false`) {
		t.Errorf("status does not report approval as unconfigured: %s", body)
	}
	allowSudo(t, s)
	body, _ := exec(t, s, map[string]any{"op": "status"})["output"].(string)
	if !strings.Contains(body, `"sudo"`) || !strings.Contains(body, `"enabled": true`) {
		t.Errorf("status does not report approval as configured: %s", body)
	}
}

// The one check that stands between the coding agent and its own approval: the
// answer has to come from root, and the agent runs as the operator.  Made at
// the op rather than by the socket mode, which admits a group by design.
func TestOnlyRootMayAnswerAnApproval(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	// uid 1000: a member of the client group, which is what the socket admits and
	// what the agent runs as.
	operator := &sockutil.Peer{PID: 42, UID: 1000, GID: 1000}
	for _, request := range []map[string]any{
		{"op": "approvals"},
		{"op": "approve", "id": "abc123", "approve": true},
	} {
		response := s.Handle(request, operator)
		if code := errorCode(t, response); code != "forbidden" {
			t.Errorf("%v as uid 1000 = %q, want forbidden: that account is the one the "+
				"agent runs as", request, code)
		}
		if detail := errorDetail(response); !strings.Contains(detail, "faramir approvals") {
			t.Errorf("the refusal does not say what to run instead: %q", detail)
		}
	}

	// And root is admitted, reaching the question rather than the check.
	if response := s.Handle(map[string]any{"op": "approvals"},
		&sockutil.Peer{PID: 1, UID: 0, GID: 0}); response["error"] != nil {
		t.Errorf("root was refused the approvals op: %v", response["error"])
	}
}

// A question a run raised is what root sees waiting, and answering it releases
// the sudo that was blocked on it.
func TestRootAnswersTheQuestionARunRaised(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)

	question, granted := raiseAndWait(t, s, "log-9")
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	if !strings.Contains(question.Prompt, "ansible-playbook site.yml") {
		t.Errorf("the question does not name the command: %q", question.Prompt)
	}

	if response := s.Handle(map[string]any{
		"op": "approve", "id": question.ID, "approve": true}, root); response["error"] != nil {
		t.Fatalf("root could not answer: %v", response["error"])
	}
	if approved := <-granted; !approved {
		t.Error("the sudo waiting on that answer was not released")
	}
	if left := s.Approval.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after an answer", len(left))
	}
}

// An approval is granted only where the kernel agrees the host is quiet, not
// where the broker's own map says so.
//
// The map and the process table can part: a cgroup teardown the executor gave
// up on, a run this process aborted without waiting for, or this process
// restarting and forgetting every run.  Any executor-uid process alive through
// an approved window can read that run's token out of /proc and sudo on it, so
// the answer that matters is the executor's, and a no from it turns the
// operator's yes into a refusal there and then rather than holding the question
// open to be answered again.
//
// It gets an error code of its own, because "your yes was refused" and "that id
// is not waiting" send an operator to different places.
func TestAnApprovalIsRefusedWhileTheHostIsNotQuiet(t *testing.T) {
	s, _ := execServer(t)
	allowSudo(t, s)
	s.Approval.Quiescent = func() (bool, string) {
		return false, "1 process(es) are running as the executor outside any brokered command"
	}

	question, granted := raiseAndWait(t, s, "log-q")
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}

	response := s.Handle(map[string]any{
		"op": "approve", "id": question.ID, "approve": true}, root)
	if code := errorCode(t, response); code != "not_quiescent" {
		t.Errorf("code = %q, want not_quiescent: a yes that was refused is not an id "+
			"nobody is waiting on", code)
	}
	if approved := <-granted; approved {
		t.Fatal("the sudo was approved while the executor said the host was not quiet")
	}
	if left := s.Approval.Questions(); len(left) != 0 {
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
	response := s.Handle(map[string]any{"op": "approve", "id": "beef00", "approve": true},
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

// raiseAndWait registers a run, puts its question, and returns the question as
// root sees it together with the channel the blocked sudo answers on.  Both
// approval tests below drive the same protocol; one copy of the poll means one
// place to change when the channel's shape does.
func raiseAndWait(t *testing.T, s *Server, logID string) (approval.Question, <-chan bool) {
	t.Helper()
	token, _ := s.Approval.Register(approval.Run{
		Argv: []string{"ansible-playbook", "site.yml"}, Cwd: "/srv", LogID: logID,
	})
	granted := make(chan bool, 1)
	go func() {
		approved, _ := s.Approval.Ask(token)
		granted <- approved
	}()
	root := &sockutil.Peer{PID: 1, UID: 0, GID: 0}
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		response := s.Handle(map[string]any{"op": "approvals", "wait_sec": 1}, root)
		if questions, _ := response["questions"].([]approval.Question); len(questions) > 0 {
			return questions[0], granted
		}
	}
	t.Fatal("no question reached root")
	return approval.Question{}, nil
}
