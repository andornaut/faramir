package escalation

// Which no it was.

import (
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

// A refusal a human typed and a question nobody answered are not the same event:
// one was judged, the other means nothing was watching. Told apart only by
// their prose they are told apart by whoever reads English, which is neither the
// log reader nor anything selecting on a field.
func TestEachEndingCarriesItsOwnCode(t *testing.T) {
	t.Run("a human said no", func(t *testing.T) {
		s := started(t, baseConfig())
		watching(t, s, false)
		token := mustRegister(s, run())
		approved, code, _ := s.Ask(procsFor(token))
		if approved {
			t.Fatal("a refusal was approved")
		}
		if code != CodeRejected {
			t.Errorf("code = %q, want %q", code, CodeRejected)
		}
	})

	t.Run("a human said yes", func(t *testing.T) {
		s := started(t, baseConfig())
		watching(t, s, true)
		token := mustRegister(s, run())
		if approved, code, _ := s.Ask(procsFor(token)); !approved || code != CodeApproved {
			t.Errorf("approved=%v code=%q, want true and %q", approved, code, CodeApproved)
		}
	})

	t.Run("nobody answered", func(t *testing.T) {
		cfg := baseConfig()
		cfg.TimeoutSec = 1
		s := started(t, cfg)
		token := mustRegister(s, run())
		approved, code, reason := s.Ask(procsFor(token))
		if approved {
			t.Fatal("a question nobody answered was approved")
		}
		if code != CodeExpired {
			t.Errorf("code = %q (%s), want %q: an expiry is not a refusal somebody typed",
				code, reason, CodeExpired)
		}
	})

	t.Run("the command ended first", func(t *testing.T) {
		s := started(t, baseConfig())
		token := mustRegister(s, run())
		asked := make(chan string, 1)
		go func() {
			_, code, _ := s.Ask(procsFor(token))
			asked <- code
		}()
		waitForQuestion(t, s)
		s.Release(token, Outcome{})
		if code := <-asked; code != CodeRunEnded {
			t.Errorf("code = %q, want %q", code, CodeRunEnded)
		}
	})

	t.Run("the host was not quiet", func(t *testing.T) {
		s := started(t, baseConfig())
		s.Quiescent = func() (bool, string) { return false, "1234 (sleep)" }
		token := mustRegister(s, run())
		asked := make(chan string, 1)
		go func() {
			_, code, _ := s.Ask(procsFor(token))
			asked <- code
		}()
		id := waitForQuestion(t, s)
		// The yes the broker turns into a no, which is neither the operator's
		// refusal nor an expiry.
		if err := s.Answer(id, true, "the test"); err == nil {
			t.Fatal("a yes was taken on a host that was not quiet")
		}
		if code := <-asked; code != CodeNotQuiescent {
			t.Errorf("code = %q, want %q", code, CodeNotQuiescent)
		}
	})

	t.Run("a token naming nothing", func(t *testing.T) {
		s := started(t, baseConfig())
		if _, code, _ := s.Ask(procsFor("0123456789abcdef")); code != CodeUnownedRun {
			t.Errorf("code = %q, want %q", code, CodeUnownedRun)
		}
	})

	t.Run("a host that grants nothing", func(t *testing.T) {
		s := started(t, config.SudoConfig{})
		if _, code, _ := s.Ask(procsFor("whatever")); code != CodeNoGrant {
			t.Errorf("code = %q, want %q", code, CodeNoGrant)
		}
	})
}

// And the code reaches the record, which is where it is read from. The prose
// stays beside it: it names the account that answered or the process that was in
// the way, and neither fits in a code.
func TestTheRecordCarriesTheCodeAndTheProse(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 1
	s := started(t, cfg)
	var entries []map[string]any
	var mu sync.Mutex
	s.Record = func(entry map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		entries = append(entries, entry)
	}
	token := mustRegister(s, run())
	s.Ask(procsFor(token))

	mu.Lock()
	defer mu.Unlock()
	if len(entries) != 1 {
		t.Fatalf("%d records for one request, want 1", len(entries))
	}
	if code, _ := entries[0]["outcome_code"].(string); code != CodeExpired {
		t.Errorf("outcome_code = %q, want %q", code, CodeExpired)
	}
	if prose, _ := entries[0]["outcome"].(string); !strings.Contains(prose, "nobody answered") {
		t.Errorf("outcome = %q, want the sentence kept beside the code", prose)
	}
}

// The last no a run was given, kept for the broker to report when the command
// ends. Without it a refusal and an expiry reach the caller alike, as sudo's
// own authentication failure, and one is worth running again and the other is
// not.
func TestARunKeepsTheNoItWasGiven(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 1
	s := started(t, cfg)
	token := mustRegister(s, run())

	if code, _ := s.Refusal(token); code != "" {
		t.Errorf("a run nobody refused reports %q", code)
	}
	s.Ask(procsFor(token))
	code, reason := s.Refusal(token)
	if code != CodeExpired {
		t.Errorf("code = %q, want %q", code, CodeExpired)
	}
	if !strings.Contains(reason, "nobody answered") {
		t.Errorf("reason = %q, want the sentence the question ended with", reason)
	}

	// Dropped with the run, so nothing outlives what it is about.
	s.Release(token, Outcome{})
	if code, _ := s.Refusal(token); code != "" {
		t.Errorf("a released run still reports %q", code)
	}
}

// An approved run has no refusal to report, so the field stays absent rather
// than saying a command that ran was turned down.
func TestAnApprovedRunKeepsNoRefusal(t *testing.T) {
	s := started(t, baseConfig())
	watching(t, s, true)
	token := mustRegister(s, run())
	if approved, _, reason := s.Ask(procsFor(token)); !approved {
		t.Fatalf("the run was not approved: %s", reason)
	}
	if code, _ := s.Refusal(token); code != "" {
		t.Errorf("an approved run reports a refusal: %q", code)
	}
}

// A run asks once per sudo, so a no it was given is not the last word: the first
// can expire while nobody is watching and the operator can approve the second.
// The refusal has to go with the yes, or a command that became root and exited
// cleanly is reported as one whose escalation expired.
func TestAYesClearsTheNoBeforeIt(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 1
	s := started(t, cfg)
	token := mustRegister(s, run())

	s.Ask(procsFor(token))
	if code, _ := s.Refusal(token); code != CodeExpired {
		t.Fatalf("the first sudo reports %q, want %q", code, CodeExpired)
	}

	watching(t, s, true)
	if approved, _, reason := s.Ask(procsFor(token)); !approved {
		t.Fatalf("the second sudo was not approved: %s", reason)
	}
	if code, reason := s.Refusal(token); code != "" {
		t.Errorf("an approved run still reports %q: %s", code, reason)
	}
}

// The wait is the question's own lifetime, so a run its deadline killed while
// the question was open still reports it. That is the case the number matters
// most in: every second of the duration was the question, and the broker reads
// it before the run is released, with the question still outstanding.
func TestAWaitIsCountedWhileTheQuestionIsStillOpen(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 30
	s := started(t, cfg)
	token := mustRegister(s, run())

	go func() { _, _, _ = s.Ask(procsFor(token)) }()
	waitForQuestion(t, s)
	time.Sleep(300 * time.Millisecond)

	if waited := s.Waited(token); waited < 200*time.Millisecond {
		t.Errorf("waited = %v with the question open, want the time it has been", waited)
	}
}

// And a second sudo joining the question another raised is the same wait, not
// another: counted per sudo, two joiners would report twice the seconds that
// passed.
func TestJoiningAQuestionDoesNotCountTheWaitTwice(t *testing.T) {
	s := started(t, baseConfig())
	token := mustRegister(s, run())

	go func() { _, _, _ = s.Ask(procsFor(token)) }()
	waitForQuestion(t, s)
	go func() { _, _, _ = s.Ask(procsFor(token)) }()
	time.Sleep(300 * time.Millisecond)

	if waited := s.Waited(token); waited > 3*time.Second {
		t.Errorf("waited = %v, which is more time than has passed", waited)
	}
}

// A run's duration is wall time and its child sits inside sudo for the whole
// question, so how long the question waited is kept apart: without it a run
// answered after a trip to the kitchen reads as a slow command.
func TestARunKeepsHowLongItWaitedToBeApproved(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 10
	s := started(t, cfg)
	token := mustRegister(s, run())

	if waited := s.Waited(token); waited != 0 {
		t.Errorf("a run that has asked nothing waited %v", waited)
	}

	// Answered after a beat, which is what the number is for.
	go func() {
		time.Sleep(300 * time.Millisecond)
		if id := waitForQuestion(t, s); id != "" {
			_ = s.Answer(id, true, "the test")
		}
	}()
	if approved, _, reason := s.Ask(procsFor(token)); !approved {
		t.Fatalf("the run was not approved: %s", reason)
	}
	waited := s.Waited(token)
	if waited < 200*time.Millisecond {
		t.Errorf("waited = %v, want about the time the answer took", waited)
	}
	if waited > 5*time.Second {
		t.Errorf("waited = %v, which is more than the question was open", waited)
	}
}
