package escalation

// What became of the run (`faramir sudo watch` reports the ending).

import (
	"testing"
	"time"
)

// approved is a run taken all the way to a yes, and the token it is held by.
// The watcher answers the question the Ask puts; the run's approved flag is what
// Release then keys the outcome off.
func approved(t *testing.T, s *Server) string {
	t.Helper()
	watching(t, s, true)
	token := mustRegister(s, run())
	if ok, _, reason := s.Ask(procsFor(token)); !ok {
		t.Fatalf("the run was not approved: %s", reason)
	}
	return token
}

// The terminal that gave root away is told what became of it, so a yes is not
// the last thing the operator hears about the command they judged.
func TestAnApprovedRunPublishesItsEnding(t *testing.T) {
	s := started(t, baseConfig())
	token := approved(t, s)

	code := 3
	s.Release(token, Outcome{LogID: "log-1", ExitCode: &code, DurationSec: 1.5,
		StatusUnknown: true})

	_, finished := s.Poll(0, "log-1")
	if finished == nil {
		t.Fatal("an approved run ended with nothing reported to the terminal that approved it")
	}
	if finished.ExitCode == nil || *finished.ExitCode != 3 {
		t.Errorf("exit code = %v, want the 3 the run ended with", finished.ExitCode)
	}
	if finished.DurationSec != 1.5 {
		t.Errorf("duration = %v, want 1.5", finished.DurationSec)
	}
	if !finished.StatusUnknown {
		t.Error("StatusUnknown was dropped, so a stand-in code reads as a signal kill")
	}
}

// Only the run the caller names. The slot is never emptied when it is read, so
// matching is the whole of what keeps a stale ending from printing under a
// question it does not belong to, and what keeps a filled slot from returning
// from every poll at once.
func TestAnEndingReachesOnlyTheCallerWaitingForIt(t *testing.T) {
	s := started(t, baseConfig())
	token := approved(t, s)
	code := 0
	s.Release(token, Outcome{LogID: "log-1", ExitCode: &code})

	if _, finished := s.Poll(0, ""); finished != nil {
		t.Error("a caller that approved nothing was told how somebody else's run ended")
	}
	if _, finished := s.Poll(0, "log-2"); finished != nil {
		t.Error("a caller waiting on one run was told about another")
	}
	if _, finished := s.Poll(0, "log-1"); finished == nil {
		t.Error("the caller waiting on this run was not told it ended")
	}
}

// A run nobody was asked about has no ending to report: no terminal is waiting
// to hear it, and a line under a question that was never put is one nobody can
// place.
func TestARunNobodyApprovedPublishesNothing(t *testing.T) {
	s := started(t, baseConfig())
	token := mustRegister(s, run())
	code := 0
	s.Release(token, Outcome{LogID: "log-1", ExitCode: &code})

	if _, finished := s.Poll(0, "log-1"); finished != nil {
		t.Error("a run that was never approved reported an ending")
	}
}

// The ending arrives when the run ends rather than when the poll runs out, so
// the line follows the command instead of trailing a whole wait behind it.
func TestAWatcherIsWokenByTheEnding(t *testing.T) {
	s := started(t, baseConfig())
	token := approved(t, s)

	go func() {
		time.Sleep(20 * time.Millisecond)
		code := 0
		s.Release(token, Outcome{LogID: "log-1", ExitCode: &code})
	}()

	start := time.Now()
	_, finished := s.Poll(5*time.Second, "log-1")
	if finished == nil {
		t.Fatal("the poll returned without the ending it was waiting for")
	}
	if waited := time.Since(start); waited > 2*time.Second {
		t.Errorf("the poll waited %v for an ending it should have been woken by", waited)
	}
}

// A run the broker never got a status for says so. A zero exit code here would
// read as a clean exit, which is the one thing the operator's only report of the
// run must not get wrong.
func TestAnEndingWithNoStatusReportsNone(t *testing.T) {
	s := started(t, baseConfig())
	token := approved(t, s)
	s.Release(token, Outcome{LogID: "log-1", Error: "the executor could not be reached"})

	_, finished := s.Poll(0, "log-1")
	if finished == nil {
		t.Fatal("a failed run reported no ending")
	}
	if finished.ExitCode != nil {
		t.Errorf("exit code = %v, want none for a run that never reported one", *finished.ExitCode)
	}
	if finished.Error == "" {
		t.Error("a run that failed reported neither a status nor a reason")
	}
}
