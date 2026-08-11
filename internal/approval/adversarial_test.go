package approval

// Adversarial probes against the approval gate: what a brokered command can do
// to the question a human is shown, rather than to the answer.
//
// These were written as the record of three gaps and now assert that each is
// closed, which is the shape to keep them in: a probe that only documents a
// weakness stops being read, and one that fails when the weakness comes back is
// the thing worth having.  What each one is defending, and what closing it cost,
// is with the mechanism in docs/design.md.
//
// The answer channel itself is not probed here.  SO_PEERCRED, `requisite` and
// `seteuid` are covered by internal/server and internal/install, and they hold.
// What follows is the other half: the prompt is the whole security argument,
// and the command it names is chosen by the caller.

import (
	"errors"
	"strings"
	"testing"
)

// The prompt is printed to the operator's terminal with %s, and a terminal obeys
// what it is sent.  The redactor strips CSI and OSC on the way in; what it
// leaves is a bare "\r" and a stray ESC, either of which rewrites what the
// reader sees.  internal/termsafe carries the measurements.
//
// The escape below is one redaction would have removed, which is the point: this
// asserts the prompt does not depend on that having happened.  Quoted rather
// than stripped, so an argument that held one is one the operator sees held it.
func TestThePromptDoesNotObeyTheArgv(t *testing.T) {
	prompt := Prompt(Run{
		Argv: []string{"ansible-playbook", "site.yml\x1b[2K\rls -la"},
		Cwd:  "/srv/ctrl",
	})
	if strings.ContainsAny(prompt, "\x1b\r\n") {
		t.Fatalf("prompt = %q, want no byte a terminal acts on", prompt)
	}
	if !strings.Contains(prompt, `\x1b[2K\r`) {
		t.Errorf("prompt = %q, want the escape shown as an escape rather than removed", prompt)
	}
	// The ordinary argument beside it is left alone: a prompt full of quotation
	// marks is one that is read less carefully.
	if !strings.Contains(prompt, "ansible-playbook \"site.yml") {
		t.Errorf("prompt = %q, want the harmless argument unquoted", prompt)
	}
}

// The cwd is the caller's too, and reaches the same terminal by the same route.
func TestThePromptDoesNotObeyTheCwd(t *testing.T) {
	prompt := Prompt(Run{Argv: []string{"true"}, Cwd: "/srv\nfaramir: run as root"})
	if strings.ContainsAny(prompt, "\x1b\r\n") {
		t.Fatalf("prompt = %q, want no byte a terminal acts on", prompt)
	}
}

// Argv is unbounded, and a question whose real content has scrolled off the top
// of a terminal is one nobody read.
func TestThePromptIsBounded(t *testing.T) {
	long := strings.Repeat("a", 10_000)
	// Every caller-chosen field, not only argv: the cwd and the resolved program
	// are the caller's too, and a 4KB cwd pushes the question off the top of the
	// screen exactly as a 4KB argument would.
	for _, tc := range []struct {
		name string
		run  Run
	}{
		{"argv", Run{Argv: []string{"playbook", long}}},
		{"cwd", Run{Argv: []string{"playbook"}, Cwd: "/" + long}},
		{"program", Run{Argv: []string{"playbook"}, Argv0Path: "/" + long}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			prompt := Prompt(tc.run)
			if len(prompt) > maxCommandChars+400 {
				t.Errorf("prompt is %d bytes, want it bounded near %d",
					len(prompt), maxCommandChars)
			}
			if !strings.Contains(prompt, "more bytes") {
				t.Errorf("prompt = %q, want the truncation said rather than silent", prompt)
			}
		})
	}
}

// The prompt names the program root will run, not only the one the caller asked
// for.  A relative argv[0] resolves against the request's cwd, which is the
// agent's working tree, so `bin/ansible-playbook` can be a file the agent wrote.
func TestThePromptNamesWhatWillActuallyRun(t *testing.T) {
	prompt := Prompt(Run{
		Argv: []string{"bin/ansible-playbook", "site.yml"}, Cwd: "/srv/ctrl",
		Argv0Path: "/srv/ctrl/bin/ansible-playbook",
	})
	if !strings.Contains(prompt, "/srv/ctrl/bin/ansible-playbook") {
		t.Errorf("prompt = %q, want the resolved program named", prompt)
	}
	// And says nothing extra when the two agree, which is the ordinary case.
	plain := Prompt(Run{
		Argv: []string{"ansible-playbook"}, Argv0Path: "ansible-playbook",
	})
	if strings.Contains(plain, "which is") {
		t.Errorf("prompt = %q, want no note where argv[0] is what runs", plain)
	}
}

// An approval takes only where something outside this server's own bookkeeping
// says the host is quiet.  The map here and the process table can part (a
// cgroup teardown that gave up, a run aborted from the broker's side, this
// process restarting), and every live executor-uid process during an approved
// window can read the run's token and sudo on it.
//
// A no fails the sudo then and there, and closes the question.  Holding it open
// for another try is the kinder-looking behaviour and the wrong one: it makes
// the operator poll the one interval in which the host has to be quiet, and
// leaves a yes standing against a condition that can change under it.
func TestAnApprovalNeedsMoreThanThisServersOwnBookkeeping(t *testing.T) {
	s := started(t, baseConfig())
	s.Quiescent = func() (bool, string) {
		return false, "2 process(es) are running as the executor outside any brokered command"
	}

	token := mustRegister(s, run())
	granted := make(chan bool, 1)
	go func() {
		approved, _ := s.Ask(token)
		granted <- approved
	}()
	id := waitForQuestion(t, s)

	err := s.Answer(id, true, "the test")
	if err == nil {
		t.Fatal("an approval took while processes of the executor's uid were unaccounted for")
	}
	if !errors.Is(err, ErrNotQuiescent) {
		t.Errorf("Answer error = %v, want ErrNotQuiescent so the caller can tell this "+
			"from an id nobody is waiting on", err)
	}
	if !strings.Contains(err.Error(), "running as the executor") {
		t.Errorf("Answer error = %v, want the executor's own reason carried through", err)
	}
	if approved := <-granted; approved {
		t.Fatal("the sudo was approved despite the answer being refused")
	}
	if len(s.Questions()) != 0 {
		t.Error("the question was left open after a yes that could not be taken")
	}
}

// A caller decides whether the host is ever quiet enough for a yes to take, so
// long as it can keep starting commands: Answer refuses to approve alongside any
// other registered run.  Holding from the moment a question is put makes the
// host drain toward the answer instead of away from it.
func TestAQuestionHoldsNewCommandsToo(t *testing.T) {
	s := started(t, baseConfig())
	s.Quiescent = func() (bool, string) { return true, "the test says so" }

	token := mustRegister(s, run())
	go func() { _, _ = s.Ask(token) }()
	id := waitForQuestion(t, s)

	if _, heldBy := s.Register(Run{Argv: []string{"true"}, Cwd: "/srv/ctrl"}); heldBy == "" {
		t.Fatal("a command started while a question was waiting, so the operator's " +
			"yes would be refused for want of a quiescence that caller controls")
	}
	if err := s.Answer(id, true, "the test"); err != nil {
		t.Fatalf("the approval did not take on a host nothing else could crowd: %v", err)
	}
}

// A question says how much of [sudo] timeout_sec is left, not only how long it
// has been there.
//
// It matters most where the answer is a second command: `faramir approve`
// without --watch prints the question, and the operator then types `faramir
// approve <id>` against a clock that started when the question was raised.  How
// long it has already waited does not tell them whether they have time.
func TestAQuestionSaysHowLongIsLeftToAnswerIt(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 10
	s := started(t, cfg)

	token := mustRegister(s, run())
	go func() { _, _ = s.Ask(token) }()
	waitForQuestion(t, s)

	question := s.Questions()[0]
	if question.ExpiresInSec <= 0 || question.ExpiresInSec > cfg.TimeoutSec {
		t.Errorf("expires_in_sec = %d, want what is left of %d",
			question.ExpiresInSec, cfg.TimeoutSec)
	}
	if question.WaitingSec+question.ExpiresInSec != cfg.TimeoutSec {
		t.Errorf("waiting %ds + expires in %ds != timeout %ds: the two describe one "+
			"clock and have to agree", question.WaitingSec, question.ExpiresInSec,
			cfg.TimeoutSec)
	}
}

// A Server with no way to ask whether the host is quiet refuses every approval.
//
// Everything else on this path fails closed, and an unwired check was the one
// way it could have failed open: the broker wires it after constructing the
// Server, so "has a quiescence check" would otherwise be a property of one
// call site rather than of the type.
func TestAnUnwiredQuiescenceCheckRefuses(t *testing.T) {
	s := started(t, baseConfig())
	s.Quiescent = nil

	token := mustRegister(s, run())
	granted := make(chan bool, 1)
	go func() {
		approved, _ := s.Ask(token)
		granted <- approved
	}()
	id := waitForQuestion(t, s)

	err := s.Answer(id, true, "the test")
	if err == nil {
		t.Fatal("an approval took on a server that cannot ask whether the host is quiet")
	}
	if !errors.Is(err, ErrNotQuiescent) {
		t.Errorf("Answer error = %v, want ErrNotQuiescent", err)
	}
	if approved := <-granted; approved {
		t.Error("the sudo was approved without the host having been checked")
	}
}
