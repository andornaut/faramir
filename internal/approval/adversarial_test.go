package approval

// Adversarial probes against the approval gate: what a brokered command can do
// to the question a human is shown, rather than to the answer.
//
// The tests below PASS, and that is the point of them.  Each one asserts the
// behaviour as it is today, so the gap it names is a fact in the suite rather
// than a claim in a document.  See ADVERSARIAL-ALLOW-SUDO.md for what each one
// costs and what closing it would cost.
//
// The answer channel itself is not probed here -- SO_PEERCRED, `requisite` and
// `seteuid` are covered by internal/server and internal/install, and they hold.
// What follows is the other half: the prompt is the whole security argument,
// and the command it names is chosen by the caller.

import (
	"strings"
	"testing"
	"time"
)

// The prompt is built from argv with nothing removed, so a caller decides what
// bytes reach the operator's terminal.  `faramir approve` prints Prompt with
// %s, and a terminal acts on what it is sent: \r returns the cursor, ESC [ 2K
// erases the line, ESC [ A moves up one.  The line a human reads is therefore
// not the line the broker composed.
//
// Nothing about this is theoretical -- argv comes over the socket as JSON
// strings, and protocol.Parse takes any string it is given.
func TestThePromptCarriesWhateverTheArgvHolds(t *testing.T) {
	hostile := Run{
		Argv: []string{"ansible-playbook", "site.yml\x1b[2K\rls -la"},
		Cwd:  "/srv/ctrl",
	}
	prompt := Prompt(hostile)
	if !strings.Contains(prompt, "\x1b[2K\r") {
		t.Fatalf("prompt = %q, want the escape sequence carried through: this test "+
			"records that the prompt is not sanitized, so it fails when it is", prompt)
	}
	// The tail is what a terminal leaves on the line after acting on the escape.
	if !strings.HasSuffix(strings.SplitN(prompt, "\x1b[2K\r", 2)[1], "ls -la in /srv/ctrl -- "+
		"approve every sudo this command makes until it ends? Type yes") {
		t.Errorf("prompt = %q, want the rewritten line to read as a whole question", prompt)
	}
}

// The cwd is the caller's too, and reaches the same terminal by the same route.
func TestThePromptCarriesWhateverTheCwdHolds(t *testing.T) {
	prompt := Prompt(Run{Argv: []string{"true"}, Cwd: "/srv\nfaramir: run as root"})
	if !strings.Contains(prompt, "\n") {
		t.Fatalf("prompt = %q, want the newline carried through", prompt)
	}
}

// A refusal is not remembered against the run it refused.  Each sudo the run
// makes afterwards raises a question of its own, without bound and without
// backoff, and each raise re-runs [sudo] notify_command.
//
// TestARefusedRunKeepsAsking is TestARefusedRequestIsDenied's other side: a no
// correctly fails that sudo, and correctly does not stand in for a yes, but it
// also does not stand in for a no.  Deny-by-default holds per request; it does
// not hold per run.  What that buys an attacker is attention: near-identical
// prompts, as many as the operator will read, until one gets a yes.
func TestARefusedRunKeepsAsking(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, false)

	token := mustRegister(s, run())
	const asks = 10
	for i := range asks {
		if approved, _ := s.Ask(token); approved {
			t.Fatalf("request %d was approved", i)
		}
	}
	if h.questions() != asks {
		t.Errorf("%d requests after a refusal put %d questions, want %d: a no is not "+
			"carried, so one run can ask as often as it likes", asks, h.questions(), asks)
	}
}

// A run may register while another run's question is unanswered, and a
// registered run is what Answer refuses to approve alongside.  So a caller that
// keeps starting commands keeps the host from ever being quiet enough for a yes
// to take: every approval is refused for want of quiescence the same caller
// controls.
//
// Availability rather than escalation, and the operator sees a refusal naming a
// command they did not start -- which is also caller-chosen text, per the two
// prompt tests above.
func TestARegisteredRunCanHoldEveryApprovalOff(t *testing.T) {
	s := started(t, baseConfig())

	token := mustRegister(s, run())
	asked := make(chan struct{})
	go func() {
		close(asked)
		_, _ = s.Ask(token)
	}()
	<-asked

	// Whatever else is running, a new command still registers: the hold applies
	// only once an approval is live, and this one never becomes live.
	noise, held := s.Register(Run{Argv: []string{"true"}, Cwd: "/srv/ctrl"})
	if held {
		t.Fatal("a run was held while nothing had been approved")
	}
	defer s.Release(noise)

	deadline := time.Now().Add(2 * time.Second)
	for {
		questions := s.Questions()
		if len(questions) > 0 {
			err := s.Answer(questions[0].ID, true, "the test")
			if err == nil {
				t.Fatal("an approval took while a second brokered command was registered")
			}
			if !strings.Contains(err.Error(), "another brokered command runs") {
				t.Fatalf("Answer error = %v, want the refusal to name the other command", err)
			}
			return
		}
		if !time.Now().Before(deadline) {
			t.Fatal("no question was raised")
		}
		time.Sleep(10 * time.Millisecond)
	}
}
