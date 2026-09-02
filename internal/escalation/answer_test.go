package escalation

// The answer channel.

import (
	"testing"
	"time"
)

// Answering a question nobody is waiting on is an error rather than a silent
// success: the operator has typed an id that has expired, and needs to know.
func TestAnsweringAnUnknownQuestionFails(t *testing.T) {
	s := started(t, baseConfig())
	if err := s.Answer("beef00", true, "the test"); err == nil {
		t.Error("answering a question nobody asked succeeded")
	}
}

// A watcher blocks until there is something to answer rather than polling, and
// gives up on its own clock so a broker that went away is noticed.
func TestPollBlocksUntilSomethingIsAsked(t *testing.T) {
	s := started(t, baseConfig())

	if got, _ := s.Poll(50*time.Millisecond, ""); len(got) != 0 {
		t.Errorf("Poll = %v with nothing waiting", got)
	}
	token := mustRegister(s, run())
	go func() { _, _, _ = s.Ask(procsFor(token)) }()

	questions, _ := s.Poll(5*time.Second, "")
	if len(questions) != 1 {
		t.Fatalf("Poll returned %d questions, want the one just asked", len(questions))
	}
	question := questions[0]
	if question.ID == "" || question.Prompt == "" {
		t.Errorf("a question with nothing to show: %+v", question)
	}
	if question.Cmd != "ansible-playbook msmtp.yml" {
		t.Errorf("cmd = %q, want the command being asked about", question.Cmd)
	}
}

// And the refusal is this one rather than a wait: the sudo comes back rather
// than blocking for [sudo] timeout_sec on a question nobody can grant.
func TestTheEarlyRefusalDoesNotBlock(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	_ = mustRegister(s, Run{Argv: []string{"playbook", "two"}})

	done := make(chan struct{})
	go func() { _, _, _ = s.Ask(procsFor(first)); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sudo blocked instead of being refused, so it is waiting out a " +
			"question that was never grantable")
	}
}

// Once the other command ends, the same run may ask: the refusal is about the
// host's state, not about this command.
func TestTheQuestionIsPutOnceTheOtherCommandEnds(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})
	if _, _, _, reason := s.pend(first, run()); reason == "" {
		t.Fatal("a question was filed with two commands registered")
	}
	s.Release(second, Outcome{})
	go func() { _, _, _ = s.Ask(procsFor(first)) }()
	waitForQuestion(t, s) // fails if none was put after the other command ended
}
