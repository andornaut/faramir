package escalation

// The operator's side: listing the questions that are open, waiting for one to
// be answered, and recording the answer.
//
// These take the Server's lock themselves and call the *Locked helpers in
// escalation.go under it, so a reader following the lock discipline is reading
// two files. The suffix is what says which of the two a function is.

import (
	"errors"
	"fmt"
	"log"
	"time"
)

// Question is one unanswered request, as the operator sees it.
type Question struct {
	ID     string `json:"id"`
	Prompt string `json:"prompt"`
	Cmd    string `json:"cmd"`
	// Host is where the command would become root.
	Host string `json:"host"`
	Cwd  string `json:"cwd"`
	// Caller is the account that asked, not the account the command would run as,
	// which is the executor's and the same on every question.
	Caller string `json:"caller"`
	// Program is what the run's argv[0] resolved to. Shown separately from Cmd
	// because they can differ: a relative argv[0] resolves against the request's
	// cwd, which the agent writes.
	//
	// Not what root will run. The question names the run that owns the sudo, that
	// being the only thing the helper's pids identify, and the sudo may be several
	// processes below it: a brokered `make` whose playbook escalates asks under
	// the make, and a brokered `sudo foo` resolves to sudo rather than to foo.
	Program string `json:"program"`
	LogID   string `json:"log_id"`
	// Received is when sudo asked, as an RFC 3339 string in the broker's own
	// timezone. Carried rather than derived from the two counters below: those
	// are what is left and how long it has been, which both move, and a reader
	// deciding whether anything was watching wants the wall clock the rest of
	// their terminal is stamped with.
	Received string `json:"received"`
	// WaitingSec says how long sudo has been sitting on this, counted from the
	// moment it asked. A second or two of it is the caller reaching the question
	// at all, so it answers whether anything was watching only at the sizes
	// where that dwarfs a round trip.
	WaitingSec int `json:"waiting_sec"`
	// ExpiresInSec is what is left of [sudo] timeout_sec, after which the
	// question is refused. It matters most where the answer is a second command
	// typed after this one was read, which is `faramir sudo ls` without
	// --watch.
	ExpiresInSec int `json:"expires_in_sec"`
}

// Questions is the one question waiting, or nothing. A slice because that is
// the shape the protocol returns, not because there can be two.
func (s *Server) Questions() []Question {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.questionsLocked()
}

func (s *Server) questionsLocked() []Question {
	pending := s.waiting
	if pending == nil {
		return []Question{}
	}
	waited := int(time.Since(pending.asked).Seconds())
	return []Question{{
		ID: pending.id, Prompt: prompt(pending.run),
		// Rendered like the command: these are the caller's strings and they are
		// printed to a terminal. Absent stays absent, safeField rendering "" as a
		// pair of quotation marks.
		Cmd: pending.run.Command(), Host: hostname(), Cwd: safeUnlessEmpty(pending.run.Cwd),
		Caller: safeComposed(pending.run.Caller),
		// Only when it says something the command does not: a relative argv[0]
		// resolves against the request's cwd, so `bin/ansible-playbook` can be a
		// file the agent wrote.
		Program: safeUnlessEmpty(pending.run.resolvedProgram()), LogID: pending.run.LogID,
		Received:     pending.asked.Format(time.RFC3339),
		WaitingSec:   waited,
		ExpiresInSec: max(0, s.config.TimeoutSec-waited),
	}}
}

// Poll is Questions for a watcher: it returns at once if there is anything for
// this caller, and otherwise blocks until there is or the wait runs out. A
// long poll rather than a subscription, the broker keeping no client state.
// awaitLogID names the run the caller approved and has not yet heard the end
// of, which is what keeps the never-emptied outcome slot from turning this into
// a spin.
func (s *Server) Poll(wait time.Duration, awaitLogID string) ([]Question, *Outcome) {
	s.mu.Lock()
	if s.stopped || s.waiting != nil || s.finishedLocked(awaitLogID) != nil {
		defer s.mu.Unlock()
		return s.questionsLocked(), s.finishedLocked(awaitLogID)
	}
	changed := s.changed
	s.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.questionsLocked(), s.finishedLocked(awaitLogID)
}

// finishedLocked is the ending this caller is waiting for, or nil.
func (s *Server) finishedLocked(awaitLogID string) *Outcome {
	if awaitLogID == "" || s.finished == nil || s.finished.LogID != awaitLogID {
		return nil
	}
	return s.finished
}

// Answer decides one question. The caller is checked to be root before this is
// reached: the account the coding agent runs as must not be able to approve
// what the agent asked for.
func (s *Server) Answer(id string, approve bool, who string) error {
	if _, err := s.find(id); err != nil {
		return err
	}
	// Outside the lock, and before it: the check is a round trip to the executor.
	// A process appearing between the two was spawned either by something already
	// running, which this check saw, or by the run being approved; a new run
	// starting in that gap is caught by the sole-occupancy check below.
	if approve {
		if s.Quiescent == nil {
			return s.refuseForNoise(id, "this broker has no way to ask whether the host "+
				"is quiet, and an escalation granted on bookkeeping alone is one nothing "+
				"checked against the process table")
		}
		if quiet, detail := s.Quiescent(); !quiet {
			return s.refuseForNoise(id, detail)
		}
	}

	s.mu.Lock()
	pending, err := s.findLocked(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// Sole occupancy: root is handed to a run only when it is the one brokered
	// command running, anything else on the executor's uid being able to read its
	// runID and ride the escalation. A refusal needs no such quiet, and refusing
	// here answers the question no rather than holding it open; see
	// refuseForNoise.
	//
	// The backstop rather than the binding check, pend and Register having
	// already refused the states this rules out, and made rather than assumed.
	// The check and the flag it stands on are set under one lock hold: a gap
	// between the two is a window in which a second command starts and rides this
	// escalation.
	if approve {
		if other := s.otherRunLocked(pending.runID); other != "" {
			s.mu.Unlock()
			return s.refuseForNoise(id, "another brokered command is registered ("+
				other+") and could ride the escalation")
		}
		if run, ok := s.runs[pending.runID]; ok {
			run.approved = true
			// The no it was given before this one is not the answer any more: left
			// standing, an earlier expiry would be reported for a command that went
			// on to become root and exit cleanly.
			run.refusedCode, run.refusedReason = "", ""
			s.runs[pending.runID] = run
		}
	}
	s.mu.Unlock()
	code, reason := CodeRejected, "rejected by "+who
	if approve {
		code, reason = CodeApproved, "approved by "+who
	}
	// Not recorded here: the answer reaches every request waiting on it through
	// `reason`, and each of those writes a record naming who answered.
	log.Printf("escalation: %s %s by %s", id,
		map[bool]string{true: "approved", false: "rejected"}[approve], who)
	s.finish(pending, approve, code, reason)
	return nil
}

// ErrNotQuiescent is what a yes becomes when the host was not quiet enough to
// take it. Exported so the broker can give it an error code of its own,
// distinct from an id that had expired.
var ErrNotQuiescent = errors.New("the host was not quiet, so this was refused")

// refuseForNoise answers a question no, on behalf of an operator who said yes.
// The question is not held open for another try: that would make the operator
// poll the one interval in which the host must be quiet, and would leave a yes
// standing against a condition that can change under it. The sudo fails now,
// and running the command again is a fresh question.
func (s *Server) refuseForNoise(id, detail string) error {
	pending, err := s.find(id)
	if err != nil {
		// Answered or expired while the check ran. Nothing to refuse.
		return err
	}
	log.Printf("escalation: %s refused rather than approved: %s", id, detail)
	s.finish(pending, false, CodeNotQuiescent, "the host was not quiet ("+detail+")")
	return fmt.Errorf("%w: %s. %s is closed; run the command again once the host "+
		"is quiet", ErrNotQuiescent, detail, id)
}

// find is findLocked for a caller that does not hold the lock.
func (s *Server) find(id string) (*escalation, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findLocked(id)
}

// findLocked is the question with this id, or why there is none.
func (s *Server) findLocked(id string) (*escalation, error) {
	if s.waiting != nil && s.waiting.id == id {
		return s.waiting, nil
	}
	return nil, fmt.Errorf("no question %s is waiting: already answered, or its "+
		"command gave up", id)
}

// Stop releases everything waiting and refuses anything later: a question
// nobody can answer any more is one sudo would otherwise sit on until its own
// timeout.
func (s *Server) Stop() {
	s.mu.Lock()
	s.stopped = true
	clear(s.runs)
	pending := s.waiting
	// A watcher's long poll is parked on this and on nothing else: it is not
	// socket I/O, so closing the connection under it does not end it and the
	// broker would wait out the poll before it could exit. Woken whether or not
	// there is a question to finish below, a watcher with nothing waiting being
	// the ordinary case.
	s.wakeLocked()
	s.mu.Unlock()
	if pending != nil {
		// Outside the lock: finish takes it.
		s.finish(pending, false, CodeBrokerStopped, "the broker stopped first")
	}
}
