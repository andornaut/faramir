package escalation

// What a request has to prove.

import (
	"strings"
	"testing"
	"time"
)

// A request from a process the executor did not fork is refused, and refused
// without asking anybody, even while a run is registered and somebody is
// watching for questions. This is the whole of what identifies a run: there is
// nothing a caller holds, so there is nothing for one to present.
func TestAProcessTheExecutorDidNotForkIsRefused(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	mustRegister(s, run())

	stranger := []int{999999}
	approved, code, _ := s.Ask(stranger)
	if approved {
		t.Error("a process no run forked was allowed to escalate")
	}
	if code != CodeUnownedRun {
		t.Errorf("code = %q, want %q", code, CodeUnownedRun)
	}
	if asked := h.questions(); asked != 0 {
		t.Errorf("%d question(s) were put about a process no run forked", asked)
	}
}

// A run this server does not hold is refused however the ancestry is shaped:
// whether a pid still names the process it was forked as is the executor's
// question, asked in that package by TestOwnerOfRefusesAReapedProcess.
func TestAnAncestryTheExecutorDoesNotOwnIsRefused(t *testing.T) {
	s := started(t, baseConfig())
	mustRegister(s, run())

	if approved, code, _ := s.Ask([]int{424242}); approved || code != CodeUnownedRun {
		t.Errorf("approved = %v, code = %q; a process no run forked was attributed "+
			"to a live run", approved, code)
	}
}

// Stop releases everything waiting rather than leaving sudo to sit until its
// own timeout after the broker has gone.
func TestStopReleasesWhatIsWaiting(t *testing.T) {
	s := New(baseConfig())
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, _, reason := s.Ask(procsFor(token))
		if approved {
			done <- "approved"
			return
		}
		done <- reason
	}()
	// Let the question reach the queue before pulling it out from under.
	for range 100 {
		if len(s.Questions()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()

	select {
	case reason := <-done:
		if reason == "approved" {
			t.Error("a request was approved by a stopping broker")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request waiting on a human outlived the broker")
	}
	if token := mustRegister(s, run()); token != "" {
		t.Error("a run was registered after Stop")
	}
}

// A command that ends takes its unanswered question with it. A question left
// filed would be shown by `faramir sudo approve` and would take a yes for a command
// that is no longer running, and it would hold the one question slot until its
// own timeout.
func TestReleasingACommandDropsItsUnansweredQuestion(t *testing.T) {
	s := started(t, baseConfig()) // TimeoutSec is 10: nothing here may wait that long
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, _, reason := s.Ask(procsFor(token))
		if approved {
			done <- "approved"
			return
		}
		done <- reason
	}()
	id := waitForQuestion(t, s)

	s.Release(token, Outcome{})

	select {
	case reason := <-done:
		if reason == "approved" {
			t.Error("a request was approved after its command ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request outlived the command it was raised for")
	}
	if left := s.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after the command ended: %v", len(left), left)
	}
	if err := s.Answer(id, true, "the operator"); err == nil {
		t.Error("a question was approved for a command that had already ended")
	}
}

// No question is put while another command is registered, and none is queued: a
// queue could only hold questions that cannot be answered yes, Answer refusing
// to approve while any other run is registered. The same argument keeps the
// first of them from being put.
func TestNoQuestionIsPutWhileAnotherCommandIsRegistered(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	// Both tokens before either asks. A pending question holds a *new*
	// registration, so the only way two commands ask at once is both registering
	// while the host was quiet, which is what a burst of brokered commands looks
	// like, and the case this refuses.
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})

	approved, _, reason := s.Ask(procsFor(first))
	if approved {
		t.Fatal("a sudo was approved while a second command shared the executor's uid")
	}
	if !strings.Contains(reason, "playbook two") {
		t.Errorf("reason = %q, want the command in the way named", reason)
	}
	if _, raised, _, _ := s.pend(second, Run{Argv: []string{"playbook", "two"}}); raised {
		t.Fatal("the second command raised a question of its own")
	}
	if len(s.Questions()) != 0 {
		t.Errorf("%d question(s) waiting, want none: neither could be granted",
			len(s.Questions()))
	}
	if h.questions() != 0 {
		t.Errorf("a human was put to %d question(s) that could only be refused",
			h.questions())
	}
}

// The refusals pend can give are told apart. A host already holding a question
// and a stopping broker send an operator looking in different places, and one
// reported as the other sends them hunting for a pending question that is not
// there.
func TestARefusalSaysWhichLimitItHit(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})
	// Two commands registered, so neither may be approved whatever a human types:
	// each could read the other's token. The refusal names the one in the way.
	if _, _, _, reason := s.pend(first, run()); !strings.Contains(reason, "playbook two") {
		t.Errorf("reason = %q, want the other running command named", reason)
	}
	if _, _, _, reason := s.pend(second, run()); !strings.Contains(reason, "playbook one") {
		t.Errorf("reason = %q, want the other running command named", reason)
	}

	// A stopping broker, which Ask reaches when Stop lands between its own lookup
	// and this call.
	stopping := New(baseConfig())
	token := mustRegister(stopping, run())
	stopping.Stop()
	_, _, code, reason := stopping.pend(token, run())
	if !strings.Contains(reason, "stopping") {
		t.Errorf("reason = %q, want the stopping broker named rather than a busy host", reason)
	}
	if code != CodeBrokerStopped {
		t.Errorf("code = %q, want %q: a caller telling this from a refusal reads the "+
			"code, not the sentence", code, CodeBrokerStopped)
	}
}
