// Package escalation lets a brokered command become root on this host, once, with
// a human's consent, and holds no credential that could do it again. Why it is
// shaped this way is docs/design.md; this is what the code must maintain.
//
//   - A run is named by the process the executor forked for it, and a sudo says
//     which run it is inside by its own ancestry. Nothing is carried in an
//     environment, so there is nothing to copy, read out of /proc or leak into a
//     log: a process cannot choose its parent, and ptrace_scope keeps a process
//     of the same uid out of another run's tree.
//   - The PAM helper walks /proc up from sudo and sends what it finds, so nothing
//     has to be threaded through PAM, and asks the broker over its socket. The
//     executor answers which of its runs owns one of those processes, being the
//     only party that knows what it forked.
//   - The broker files a question, a human answers it through `faramir
//     approve`, and the answer releases every request from that one command.
//
// Optional: with no [sudo] exec_user nothing is granted and no question can be
// raised.
package escalation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
)

const (
	// How long the notifier may run before it is killed. It announces a pending
	// question and returns nothing, so nothing waits on it.
	notifyTimeout = 10 * time.Second
)

// A pid is enough, and a start time is not available to the party that would
// have to record one. The executor runs as the uid every brokered command runs
// as; a command that execs a setuid binary -- `sudo` itself, which is the whole
// point here -- gets a root-owned /proc entry, and ProtectProc=invisible then
// hides it from that uid. So the executor cannot read the start time of the child
// it just forked.
//
// It does not need one. A pid is unique among live processes, and the kernel does
// not reuse it until the process is reaped: the executor holds each child unreaped
// for exactly as long as it owns the run, so no other process can be wearing that
// number while an escalation is attributed to it.

type Server struct {
	config config.SudoConfig

	// Record writes one audit entry per request. Set by the broker; nil records
	// nothing, which is the case in tests.
	Record func(map[string]any)

	// Quiescent asks the kernel what this server only believes: is any process of
	// the executor's uid alive outside the runs it knows about? Such a process is
	// one this server cannot attribute to anything a human approved, and the map
	// below can part from the process table -- a teardown that does not finish, a
	// run aborted from the broker's side, this process restarting.
	//
	// Set by the broker to a call on the executor, the only account that can see
	// those processes. Nil refuses every escalation.
	Quiescent func() (quiet bool, detail string)

	// Owner says which run forked one of these processes, or "" for none of them.
	// The executor answers it, being the only party that knows what it forked; the
	// ancestry comes from the PAM helper, and neither end takes the asking
	// process's word for anything.
	//
	// Set by the broker to a call on the executor. Nil refuses every escalation.
	Owner func(ancestors []int) (runID, detail string)

	mu sync.Mutex
	// runs is what is in flight, keyed by the id the executor knows each run's
	// forked process by.
	runs map[string]Run
	// waiting is the question a human has not answered yet, or nil. One, never a
	// queue: the second task of a playbook joins the question the first raised,
	// and a second command is refused rather than filed behind it. A field
	// rather than a map keyed by runID, so "at most one" is what the type says.
	waiting *escalation
	// changed is closed and replaced whenever waiting does, so `faramir sudo ls
	// --watch` can block on the next change rather than poll for it.
	changed chan struct{}
	// finished is how the last approved run ended, for the terminal that approved
	// it. One, for the same reason waiting is one: an approved run holds every
	// other brokered command until it ends. Never emptied when it is read, so
	// two watchers both see the ending and neither consumes the other's; a caller
	// names the run it is waiting on and is told about that one only.
	finished *Outcome
	stopped  bool
}

// Outcome is how an approved run ended. It reaches the operator over the same
// long poll the question arrived on, so the terminal that gave root away says
// what became of it without reading the audit log.
type Outcome struct {
	// LogID is the exec record, and what a caller matches against: the question
	// carried the same id, so the line prints under the question it belongs to.
	LogID string `json:"log_id"`
	// ExitCode is nil when the broker never got a status for the run, which is
	// what Error then says. A pointer rather than an int: a zero would read as a
	// clean exit.
	ExitCode    *int    `json:"exit_code"`
	DurationSec float64 `json:"duration_sec"`
	// WaitedSec is how much of DurationSec the command spent blocked on its own
	// escalation. Reported beside it rather than subtracted from it: the exec
	// timeout is enforced against the same wall clock the duration measures.
	WaitedSec float64 `json:"waited_sec,omitempty"`
	TimedOut  bool    `json:"timed_out"`
	// StatusUnknown marks ExitCode as a stand-in for a status the executor never
	// reported, so a 137 here is not read as a signal kill. The run response and
	// audit record carry the same flag.
	StatusUnknown bool `json:"status_unknown,omitempty"`
	// Error is the broker's own failure, already through the redaction the audit
	// record gets: this is printed to a terminal by the same route the question
	// was.
	Error string `json:"error"`
}

// escalation is one unanswered question. Every request for the same command
// waits on the same one.
type escalation struct {
	id    string
	runID string
	run   Run
	asked time.Time

	// done is closed once answered, expired or dropped; the fields above it are
	// written before the close and read after, so the channel is the barrier.
	done     chan struct{}
	once     sync.Once
	approved bool
	code     string
	reason   string
}

// How a question ended, as one word rather than the sentence beside it: a
// refusal a human typed and a question nobody answered are not the same event,
// and nothing selecting on a field can tell them apart by their prose. The
// `outcome` beside this stays the sentence, naming the account that answered or
// the command that held the host.
const (
	CodeApproved      = "approved"
	CodeRejected      = "rejected"
	CodeExpired       = "expired"
	CodeNotQuiescent  = "not_quiescent"
	CodeRunEnded      = "run_ended"
	CodeBrokerStopped = "broker_stopped"
	CodeOtherCommand  = "other_command"
	CodeUnnamed       = "unnamed_question"
	CodeUnownedRun    = "unowned_run"
	CodeNoGrant       = "no_grant"
)

// owner asks the executor which run forked one of these processes. Nil Owner is
// a refusal rather than a pass: without it nothing can attribute a sudo to a
// command, and an escalation nobody can attribute is what this exists to avoid.
func (s *Server) owner(ancestors []int) (runID, detail string) {
	if len(ancestors) == 0 {
		return "", "the request named no processes"
	}
	if s.Owner == nil {
		return "", "the executor cannot be asked what it forked"
	}
	return s.Owner(ancestors)
}

func New(cfg config.SudoConfig) *Server {
	return &Server{
		config:  cfg,
		runs:    map[string]Run{},
		changed: make(chan struct{}),
	}
}

// Enabled reports whether this host granted the executor anything to ask about.
// exec_user names the account the sudoers entry was written for, so its absence
// is an install that never passed --allow-sudo.
func (s *Server) Enabled() bool { return s.config.ExecUser != "" }

// Register records the command a run id stands for and returns the id. Empty
// where nothing is granted, which the broker reads as a run to confine to a
// cgroup of the executor's own choosing rather than to a named one.
//
// heldBy is the serialisation: while one command holds an escalation no other
// brokered command may start. Nothing is carried in an environment for a second
// command to read, but the two share the executor's uid, and one that can ptrace
// its way into the approved run's tree is inside that run as far as an escalation
// is concerned, ancestry being what attributes one.
// Registering a run also blocks a new escalation, Answer requiring sole
// occupancy. A merely pending question holds a new command too, or a caller
// free to keep starting commands decides whether the host is ever quiet enough
// for a yes to take; the cost is that one unanswered question stalls unrelated
// work for up to [sudo] timeout_sec.
func (s *Server) Register(run Run) (runID, heldBy string) {
	if !s.Enabled() {
		return "", ""
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// Without a runID the broker cannot say what it is approving, and an
		// unnamed escalation is the thing this exists to avoid.
		log.Printf("escalation: no randomness for a runID (%v); this command cannot sudo", err)
		return "", ""
	}
	runID = hex.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return "", ""
	}
	// The reason, not a bool: `escalation_in_progress` is terminal, so this
	// message is all the caller gets. The sudo-side refusal in pend names the
	// holding command too.
	if why := s.holdLocked(); why != "" {
		log.Printf("escalation: holding a new command: %s", why)
		return "", why
	}
	s.runs[runID] = run
	return runID, ""
}

// holdLocked says why a new brokered command may not start now, or "".
func (s *Server) holdLocked() string {
	if approved := s.escalationLiveLocked(); approved != "" {
		return approved + " holds an escalation"
	}
	if waiting := s.waitingLocked(); waiting != "" {
		return waiting + " is waiting to be approved"
	}
	return ""
}

// waitingLocked names the command with a question outstanding, or "".
func (s *Server) waitingLocked() string {
	if s.waiting == nil {
		return ""
	}
	return s.waiting.run.Command()
}

// waitingForLocked is the outstanding question if it belongs to this runID, or
// nil. The runID comparison is what the map key used to do.
func (s *Server) waitingForLocked(runID string) *escalation {
	if s.waiting != nil && s.waiting.runID == runID {
		return s.waiting
	}
	return nil
}

// escalationLiveLocked names the command whose escalation currently holds the
// host, or "". At most one is ever live: approving requires sole occupancy and
// a live escalation holds every new run.
func (s *Server) escalationLiveLocked() string {
	for _, run := range s.runs {
		if run.approved {
			return run.Command()
		}
	}
	return ""
}

// otherRunLocked names a registered run whose runID is not the given one, or
// "": a second process on the executor's uid, in flight while root is handed
// out, is what could ride the escalation.
func (s *Server) otherRunLocked(runID string) string {
	for t, run := range s.runs {
		if t != runID {
			return run.Command()
		}
	}
	return ""
}

// Release drops a runID when its command ends, which is what makes an approval
// die with the run it was given for. The command's unanswered question goes
// with it: one left filed would take a yes for a command that is no longer
// running, and would hold the one question slot until it timed out.
//
// outcome is published only for a run somebody approved; no terminal is waiting
// to hear the end of one nobody was asked about.
func (s *Server) Release(runID string, outcome Outcome) {
	if runID == "" {
		return
	}
	s.mu.Lock()
	run, known := s.runs[runID]
	delete(s.runs, runID)
	if known && run.approved {
		s.finished = &outcome
		// So a watcher parked on the long poll prints the ending when the run ends
		// rather than up to a whole wait later.
		s.wakeLocked()
	}
	pending := s.waitingForLocked(runID)
	s.mu.Unlock()
	if pending != nil {
		// Outside the lock: finish takes it.
		s.finish(pending, false, CodeRunEnded, "the command ended first")
	}
}

// Ask is the whole of what a sudo asks for: may this command become root? It
// blocks until a human answers, the question expires, or the broker stops. The
// caller is the PAM helper's request, which the broker has already checked came
// from root, and sudo is blocked on it, which is what makes the wait a password
// prompt from sudo's point of view.
func (s *Server) Ask(ancestors []int) (approved bool, code, reason string) {
	if !s.Enabled() {
		return false, CodeNoGrant, "this host grants no escalation"
	}
	runID, detail := s.owner(ancestors)
	s.mu.Lock()
	run, known := s.runs[runID]
	s.mu.Unlock()
	if runID == "" || !known {
		// Blocked rather than asked about: an escalation that names no command is
		// one a human cannot judge. This is what a `sudo` typed by hand as the
		// executor's account looks like, and what one whose run has already ended
		// looks like too.
		log.Printf("escalation: refusing a request no running command owns (%s)", detail)
		s.record(map[string]any{
			"log_id": audit.NewLogID(), "op": "escalate", "approved": false,
			"outcome_code": CodeUnownedRun,
			"outcome":      "no running command owns the asking process: " + detail,
		})
		return false, CodeUnownedRun,
			"no brokered command made this request"
	}

	approved, prompted, code, reason := s.ask(runID, run)
	if !approved {
		s.refuse(runID, code, reason)
	}
	s.record(map[string]any{
		"log_id": audit.NewLogID(), "op": "escalate", "approved": approved,
		"prompted": prompted, "cmd": run.Argv, "cwd": run.Cwd,
		"run_log_id": run.LogID, "outcome_code": code, "outcome": reason,
	})
	if !approved {
		log.Printf("escalation: %q was not approved (%s): %s", run.Command(), code, reason)
	}
	return approved, code, reason
}

// refuse keeps the no this run was given, for the broker to report when the
// command ends. Dropped with the run.
func (s *Server) refuse(runID, code, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if run, known := s.runs[runID]; known {
		run.refusedCode, run.refusedReason = code, reason
		s.runs[runID] = run
	}
}

// startWaitingLocked starts the clock on a run whose question has just been
// filed, unless one is already running: a second sudo joining the same question
// is the same wait, not another.
func (s *Server) startWaitingLocked(runID string) {
	if run, known := s.runs[runID]; known && run.waitingSince.IsZero() {
		run.waitingSince = time.Now()
		s.runs[runID] = run
	}
}

// stopWaitingLocked folds the question just settled into the run's total.
func (s *Server) stopWaitingLocked(runID string) {
	run, known := s.runs[runID]
	if !known || run.waitingSince.IsZero() {
		return
	}
	run.waited += time.Since(run.waitingSince)
	run.waitingSince = time.Time{}
	s.runs[runID] = run
}

// Waited is how long this run has spent held by its questions, including one
// still open: a run its own deadline killed ends while its question is still
// outstanding.
func (s *Server) Waited(runID string) time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.runs[runID]
	if run.waitingSince.IsZero() {
		return run.waited
	}
	return run.waited + time.Since(run.waitingSince)
}

// Refusal is the last no a run was given, or empty where it was given none.
// Read by the broker when the command ends, so a caller is told why its sudo
// failed rather than being left with sudo's own account of it.
func (s *Server) Refusal(runID string) (code, reason string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	run := s.runs[runID]
	return run.refusedCode, run.refusedReason
}

// ask reports whether this request may sudo, and whether it was the one that
// put the question.
//
// One question per brokered command, not per sudo: ansible-playbook calls sudo
// once per become'd task. Not sudo's timestamp by another name, which is a
// stretch of time anything can start a command inside; this is scoped to the
// command the human was shown, dies when the run ends, and cannot be reached by
// a second run.
func (s *Server) ask(runID string, run Run) (approved, prompted bool, code, reason string) {
	pending, raised, refusedCode, refused := s.pend(runID, run)
	if pending == nil {
		return false, false, refusedCode, refused
	}
	if raised {
		// Best-effort and answerless: it says a question is waiting, and the answer
		// comes back over a channel this cannot reach.
		s.notify(pending)
		// One timer per question rather than per request, so the joiners of a
		// question expire with it rather than each on their own clock.
		go s.expire(pending)
	}
	<-pending.done
	return pending.approved, raised, pending.code, pending.reason
}

// pend files the question, or hands back the one this command already raised.
// The second return is whether this call is the one that raised it; the last
// two are why no question could be filed, when none was.
func (s *Server) pend(runID string, run Run) (*escalation, bool, string, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-checked under the lock: the requests of a playbook arrive in a rush, and
	// one that read "not approved" outside it may have been overtaken.
	if s.runs[runID].approved {
		answered := &escalation{done: make(chan struct{}), approved: true,
			code:   CodeApproved,
			reason: "covered by this command's escalation"}
		close(answered.done)
		return answered, false, "", ""
	}
	if existing := s.waitingForLocked(runID); existing != nil {
		s.startWaitingLocked(runID)
		return existing, false, "", ""
	}
	if s.stopped {
		return nil, false, CodeBrokerStopped, "the broker is stopping"
	}
	// A question is filed only by a command that is the only one registered:
	// Answer would refuse to approve alongside another run anyway, so filing it
	// would spend a human's attention on a prompt whose only outcome is a
	// refusal. Requests from the same run joined their question above, so this
	// refuses another command rather than another sudo.
	if other := s.otherRunLocked(runID); other != "" {
		return nil, false, CodeOtherCommand, fmt.Sprintf(
			"%s is also running; root goes only to a command running alone. "+
				"Run this again once that one has finished", other)
	}
	id := newID()
	if id == "" {
		return nil, false, CodeUnnamed, "this question could not be named"
	}
	pending := &escalation{
		id: id, runID: runID, run: run, asked: time.Now(),
		done: make(chan struct{}),
	}
	s.waiting = pending
	s.startWaitingLocked(runID)
	s.wakeLocked()
	log.Printf("escalation: %s is waiting to be approved: %s", pending.id, run.Command())
	return pending, true, "", ""
}

// finish answers a question once, releasing every request waiting on it. It
// does not set the run's approved flag: Answer does that under the same lock as
// its sole-occupancy check, a gap between the two being a window a second run
// could start in and ride the escalation. expire and Stop reach here too,
// always with approved=false.
func (s *Server) finish(pending *escalation, approved bool, code, reason string) {
	pending.once.Do(func() {
		s.mu.Lock()
		pending.approved, pending.code, pending.reason = approved, code, reason
		s.stopWaitingLocked(pending.runID)
		// Only if it is still the outstanding one: a runID released and
		// re-registered would otherwise lose its own.
		if s.waiting == pending {
			s.waiting = nil
		}
		s.wakeLocked()
		s.mu.Unlock()
		close(pending.done)
	})
}

// expire drops a question nobody answered. Deny by default: silence is a no,
// and a request that waited is one sudo has been sitting on.
func (s *Server) expire(pending *escalation) {
	timer := time.NewTimer(time.Duration(s.config.TimeoutSec) * time.Second)
	defer timer.Stop()
	select {
	case <-pending.done:
	case <-timer.C:
		s.finish(pending, false, CodeExpired,
			fmt.Sprintf("nobody answered within %ds", s.config.TimeoutSec))
	}
}

// wakeLocked releases everything blocked on the next change. Called with the
// lock held.
func (s *Server) wakeLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// notify announces a pending question, and reads nothing back. Whatever it
// runs cannot approve anything: the answer comes over the broker socket from a
// caller SO_PEERCRED says is root.
func (s *Server) notify(pending *escalation) {
	if len(s.config.NotifyCommand) == 0 {
		return
	}
	text := prompt(pending.run)
	argv := make([]string, 0, len(s.config.NotifyCommand))
	for _, arg := range s.config.NotifyCommand {
		arg = strings.ReplaceAll(arg, "{prompt}", text)
		argv = append(argv, strings.ReplaceAll(arg, "{id}", pending.id))
	}
	// The kill runs from inside cmd.Wait: a goroutine signalling on its own could
	// fire after the process was reaped, and the kernel reuses a pid, so the
	// signal would reach an unrelated process group of the broker's uid.
	ctx, cancel := context.WithTimeout(context.Background(), notifyTimeout)
	cmd := exec.CommandContext(ctx, argv[0], argv[1:]...)
	// The broker's own environment is never inherited by anything it starts.
	cmd.Env = []string{"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	// Its own process group, so the deadline reaches whatever the notifier itself
	// started: a notifier that hangs must not outlive the question it announced.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error { return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) }
	// Honoured by Wait alone, which is why the wait below is cmd.Wait rather than
	// cmd.Process.Wait: a group kill that leaves the leader standing is still
	// bounded, by a SIGKILL to the process itself.
	cmd.WaitDelay = time.Second
	if err := cmd.Start(); err != nil {
		cancel()
		log.Printf("escalation: cannot run the notifier %s: %v", argv[0], err)
		return
	}
	go func() {
		defer cancel()
		_ = cmd.Wait()
	}()
}
