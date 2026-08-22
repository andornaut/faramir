package escalation

// Adversarial probes against the escalation gate: what a brokered command can do
// to the question a human is shown, rather than to the answer. Each asserts a
// gap is closed rather than documenting that it is open, a probe that only
// documents a weakness being one that stops being read. What each defends, and
// what it cost, is with the mechanism in docs/design.md.
//
// The answer channel itself is not probed here: SO_PEERCRED, `requisite` and
// `seteuid` are covered by internal/server and internal/install. This is the
// other half, the prompt being the whole security argument and the command it
// names being chosen by the caller.

import (
	"errors"
	"strings"
	"testing"
)

// The prompt is printed to the operator's terminal with %s, and a terminal obeys
// what it is sent. The redactor strips CSI and OSC on the way in; what it
// leaves is a bare "\r" and a stray ESC, either of which rewrites what the
// reader sees. internal/termsafe carries the measurements.
//
// The escape below is one redaction would have removed, which is the point: this
// asserts the prompt does not depend on that having happened. Quoted rather
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

// Argv is unbounded, and a question whose real content has scrolled off the top
// of a terminal is one nobody read.
func TestThePromptIsBounded(t *testing.T) {
	prompt := Prompt(Run{Argv: []string{"playbook", strings.Repeat("a", 10_000)}})
	if len(prompt) > maxCommandChars+400 {
		t.Errorf("prompt is %d bytes, want it bounded near %d", len(prompt), maxCommandChars)
	}
	if !strings.Contains(prompt, "more bytes") {
		t.Errorf("prompt = %q, want the truncation said rather than silent", prompt)
	}
}

// asked is the question the operator is shown for one run, prompt and fields
// alike, which is what the probes below are about: the fields carry the caller's
// strings too, and reach the same terminal by the same route.
func asked(t *testing.T, r Run) Question {
	t.Helper()
	s := started(t, baseConfig())
	go s.Ask(procsFor(mustRegister(s, r)))
	waitForQuestion(t, s)
	return s.Questions()[0]
}

// The cwd and the program are the caller's, printed under the prompt, and a 4KB
// cwd pushes the question off the top of the screen exactly as a 4KB argument
// would.
func TestTheQuestionsFieldsDoNotObeyTheCaller(t *testing.T) {
	long := strings.Repeat("a", 10_000)
	question := asked(t, Run{
		Argv:      []string{"playbook"},
		Cwd:       "/srv\nfaramir: run as root\x1b[2K" + long,
		Argv0Path: "/srv\rbin/playbook" + long,
	})
	for _, field := range []struct{ name, value string }{
		{"cwd", question.Cwd}, {"program", question.Program},
	} {
		if strings.ContainsAny(field.value, "\x1b\r\n") {
			t.Errorf("%s = %q, want no byte a terminal acts on", field.name, field.value)
		}
		if len(field.value) > maxCommandChars+400 {
			t.Errorf("%s is %d bytes, want it bounded near %d",
				field.name, len(field.value), maxCommandChars)
		}
		if !strings.Contains(field.value, "more bytes") {
			t.Errorf("%s = %q, want the truncation said rather than silent",
				field.name, field.value)
		}
	}
}

// The question names the program the executor resolved, not only the string the
// caller asked for. A relative argv[0] resolves against the request's cwd, which
// is the agent's working tree, so `bin/ansible-playbook` can be a file the agent
// wrote.
//
// Not the program that becomes root: the sudo may be several processes below the
// run, and what the helper identifies is the run rather than the sudo.
func TestTheQuestionNamesTheResolvedProgram(t *testing.T) {
	question := asked(t, Run{
		Argv: []string{"bin/ansible-playbook", "site.yml"}, Cwd: "/srv/ctrl",
		Argv0Path: "/srv/ctrl/bin/ansible-playbook",
	})
	if question.Program != "/srv/ctrl/bin/ansible-playbook" {
		t.Errorf("program = %q, want the resolved program named", question.Program)
	}
	// And says nothing where the two agree, which is the ordinary case: a field
	// repeating the command is one more line between the reader and the command.
	plain := asked(t, Run{Argv: []string{"ansible-playbook"}, Argv0Path: "ansible-playbook"})
	if plain.Program != "" {
		t.Errorf("program = %q, want no field where argv[0] is what runs", plain.Program)
	}
}

// An escalation takes only where something outside this server's own bookkeeping
// says the host is quiet. The map here and the process table can part (a
// cgroup teardown that gave up, a run aborted from the broker's side, this
// process restarting), and every live executor-uid process during an approved
// window can read the run's token and sudo on it.
//
// A no fails the sudo then and there, and closes the question. Holding it open
// for another try is the kinder-looking behaviour and the wrong one: it makes
// the operator poll the one interval in which the host has to be quiet, and
// leaves a yes standing against a condition that can change under it.
func TestAnEscalationNeedsMoreThanThisServersOwnBookkeeping(t *testing.T) {
	s := started(t, baseConfig())
	s.Quiescent = func() (bool, string) {
		return false, "2 process(es) are running as the executor outside any brokered command"
	}

	token := mustRegister(s, run())
	granted := make(chan bool, 1)
	go func() {
		approved, _, _ := s.Ask(procsFor(token))
		granted <- approved
	}()
	id := waitForQuestion(t, s)

	err := s.Answer(id, true, "the test")
	if err == nil {
		t.Fatal("an escalation took while processes of the executor's uid were unaccounted for")
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
// other registered run. Holding from the moment a question is put makes the
// host drain toward the answer instead of away from it.
func TestAQuestionHoldsNewCommandsToo(t *testing.T) {
	s := started(t, baseConfig())
	s.Quiescent = func() (bool, string) { return true, "the test says so" }

	token := mustRegister(s, run())
	go func() { _, _, _ = s.Ask(procsFor(token)) }()
	id := waitForQuestion(t, s)

	if _, heldBy := s.Register(Run{Argv: []string{"true"}, Cwd: "/srv/ctrl"}); heldBy == "" {
		t.Fatal("a command started while a question was waiting, so the operator's " +
			"yes would be refused for want of a quiescence that caller controls")
	}
	if err := s.Answer(id, true, "the test"); err != nil {
		t.Fatalf("the escalation did not take on a host nothing else could crowd: %v", err)
	}
}

// A question says how much of [escalation] timeout_sec is left, not only how long it
// has been there.
//
// It matters most where the answer is a second command: `faramir approve`
// without --watch prints the question, and the operator then types `faramir
// approve <id>` against a clock that started when the question was raised. How
// long it has already waited does not tell them whether they have time.
func TestAQuestionSaysHowLongIsLeftToAnswerIt(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 10
	s := started(t, cfg)

	token := mustRegister(s, run())
	go func() { _, _, _ = s.Ask(procsFor(token)) }()
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

// A Server with no way to ask whether the host is quiet refuses every escalation.
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
		approved, _, _ := s.Ask(procsFor(token))
		granted <- approved
	}()
	id := waitForQuestion(t, s)

	err := s.Answer(id, true, "the test")
	if err == nil {
		t.Fatal("an escalation took on a server that cannot ask whether the host is quiet")
	}
	if !errors.Is(err, ErrNotQuiescent) {
		t.Errorf("Answer error = %v, want ErrNotQuiescent", err)
	}
	if approved := <-granted; approved {
		t.Error("the sudo was approved without the host having been checked")
	}
}
