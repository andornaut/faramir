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
// Optional: with no [escalation] exec_user nothing is granted and no question can be
// raised.
package escalation

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/termsafe"
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

// Run is the brokered command a request is made on behalf of. Naming it is
// what makes the answer worth anything: an approval the human cannot attribute
// to a command they initiated grants root to whatever asked.
type Run struct {
	// Argv is the command the broker started, already redacted: a caller can put
	// a value in argv even though the broker never does, and this reaches a
	// terminal and the audit log.
	Argv []string
	Cwd  string
	// Argv0Path is what the broker resolved Argv[0] to, and so the program root
	// will actually run. A relative Argv[0] resolves against the request's cwd,
	// which is the agent's working tree, so the two can name different files.
	Argv0Path string
	// LogID is the exec record this belongs to, so the log reads in both
	// directions: what a command was approved for, and what an approval was
	// spent on.
	LogID string
	// Caller is the account that asked for the command, which is not the one that
	// would run it: every brokered command runs as the executor, and more than
	// one account can be in the client group.
	Caller string

	// approved is set once a human has said yes to this run, and is what makes
	// the rest of its sudos free of a second question. Not exported: a caller
	// registering a run pre-approved would be an escalation nobody answered.
	approved bool

	// refusedCode and refusedReason are the last no this run was given, kept so
	// the broker can say why the command failed: a refusal and an expiry both
	// reach the caller as sudo's own authentication failure, and which one it was
	// decides whether running it again is worth anything.
	refusedCode   string
	refusedReason string

	// waited is how long this run's questions have held it, and waitingSince is
	// when the one outstanding began, zero where none is. Duration is wall time
	// from fork to exit, so without this a slowly answered question reads as a
	// slow command. The question's lifetime rather than each sudo's own wait,
	// which would double-count a sudo that joined a question another raised.
	waited       time.Duration
	waitingSince time.Time
}

// resolvedProgram is what argv[0] resolved to when that is not what argv[0]
// says, and "" when the two agree.
func (r Run) resolvedProgram() string {
	if len(r.Argv) == 0 || r.Argv0Path == "" || r.Argv0Path == r.Argv[0] {
		return ""
	}
	return r.Argv0Path
}

// maxCommandChars bounds what a question spends on the command. Argv is the
// caller's and can be as long as it likes; a question whose content has
// scrolled off the top of a terminal is one nobody read. The audit record
// keeps the whole of it.
const maxCommandChars = 240

// Command is the run as one line, rendered for a terminal. Every string in it
// is the caller's and reaches the operator through `faramir escalations`, the
// refusal messages and [escalation] notify_command, so left raw a run could
// return the cursor with a "\r" and overwrite the question it is judged on.
// termsafe says what survives that rendering.
func (r Run) Command() string {
	parts := make([]string, 0, len(r.Argv))
	for _, arg := range r.Argv {
		parts = append(parts, termsafe.Arg(arg))
	}
	return termsafe.Bound(strings.Join(parts, " "), maxCommandChars)
}

// safeField is termsafe.Field at this package's bound, for one field of a
// question rather than one argument of a command.
func safeField(value string) string { return termsafe.Field(value, maxCommandChars) }

// safeComposed is for a field the broker wrote rather than took from a caller:
// escaped and bounded like the rest, and not quoted. safeField quotes anything
// holding a space, which is noise around the broker's own words.
func safeComposed(value string) string {
	if value == "" {
		return ""
	}
	return termsafe.Bound(termsafe.Line(value), maxCommandChars)
}

// safeUnlessEmpty is safeField for a field a caller drops when it is absent.
func safeUnlessEmpty(value string) string {
	if value == "" {
		return ""
	}
	return safeField(value)
}

type Server struct {
	config config.EscalationConfig

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
	// changed is closed and replaced whenever waiting does, so `faramir escalations
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
	CodeDenied        = "denied"
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
		return "", "this broker cannot ask the executor what it forked"
	}
	return s.Owner(ancestors)
}

func New(cfg config.EscalationConfig) *Server {
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
// work for up to [escalation] timeout_sec.
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
		s.finish(pending, false, CodeRunEnded, "the command ended before this was answered")
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
		// Refused rather than asked about: an escalation that names no command is
		// one a human cannot judge. This is what a `sudo` typed by hand as the
		// executor's account looks like, and what one whose run has already ended
		// looks like too.
		log.Printf("escalation: refusing a request no running command owns (%s)", detail)
		s.record(map[string]any{
			"log_id": audit.NewLogID(), "op": "escalate", "approved": false,
			"outcome_code": CodeUnownedRun,
			"outcome":      "no running command owns the process that asked: " + detail,
		})
		return false, CodeUnownedRun,
			"this request comes from no brokered command, so there is nothing to approve"
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
			reason: "covered by the escalation given for this command"}
		close(answered.done)
		return answered, false, "", ""
	}
	if existing := s.waitingForLocked(runID); existing != nil {
		s.startWaitingLocked(runID)
		return existing, false, "", ""
	}
	if s.stopped {
		return nil, false, CodeBrokerStopped,
			"the broker is stopping, so nothing can be approved now"
	}
	// A question is filed only by a command that is the only one registered:
	// Answer would refuse to approve alongside another run anyway, so filing it
	// would spend a human's attention on a prompt whose only outcome is a
	// refusal. Requests from the same run joined their question above, so this
	// refuses another command rather than another sudo.
	if other := s.otherRunLocked(runID); other != "" {
		return nil, false, CodeOtherCommand, fmt.Sprintf("%s is also running, and root is handed to a "+
			"brokered command only when it is the only one: the two share the "+
			"executor's uid, so the other could read this one's runID and ride the "+
			"escalation. Run this again once that one has finished", other)
	}
	id := newID()
	if id == "" {
		return nil, false, CodeUnnamed,
			"this question could not be named, so nothing could answer it"
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
	prompt := Prompt(pending.run)
	argv := make([]string, 0, len(s.config.NotifyCommand))
	for _, arg := range s.config.NotifyCommand {
		arg = strings.ReplaceAll(arg, "{prompt}", prompt)
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

// newID names a question in something a person can type: it is read off one
// terminal and typed into another, and only one question is outstanding at a
// time. Empty when there is no randomness, and the caller then refuses the
// request rather than substituting a constant.
func newID() string {
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
	}
	return hex.EncodeToString(raw[:])
}

// Prompt is what the human is asked: one line and the command, so the answer
// means something. The host, the cwd and the program root will run are fields
// of the Question, printed under it. Exported so a test, the CLI and the
// notifier agree on it.
func Prompt(run Run) string {
	return fmt.Sprintf("%s `%s`", PromptPrefix, run.Command())
}

// PromptPrefix is the question without the command, for the terminal that
// prints the command on a line of its own below it. The notifier gets the
// whole sentence, having no second line to put one on.
const PromptPrefix = "faramir: Approve this command to run as root?"

// hostname is what the question says it is about, and never empty: a question
// that names no host is one an operator watching two of them cannot place.
func hostname() string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		return "this host"
	}
	return safeField(host)
}

func (s *Server) record(entry map[string]any) {
	if s.Record != nil {
		s.Record(entry)
	}
}

// --------------------------------------------------------------------------
// The answer channel (reached through the broker socket, root only)
// --------------------------------------------------------------------------

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
	// Program is what argv[0] resolved to, and so what root will run. Shown
	// separately from Cmd because they can differ: a relative argv[0] resolves
	// against the request's cwd, which the agent writes.
	Program string `json:"program"`
	LogID   string `json:"log_id"`
	// WaitingSec says how long sudo has been sitting on this, counted from the
	// moment it asked. A second or two of it is the caller reaching the question
	// at all, so it answers whether anything was watching only at the sizes
	// where that dwarfs a round trip.
	WaitingSec int `json:"waiting_sec"`
	// ExpiresInSec is what is left of [escalation] timeout_sec, after which the
	// question is refused. It matters most where the answer is a second command
	// typed after this one was read, which is `faramir escalations` without
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
		ID: pending.id, Prompt: Prompt(pending.run),
		// Rendered like the command: these are the caller's strings and they are
		// printed to a terminal. Absent stays absent, safeField rendering "" as a
		// pair of quotation marks.
		Cmd: pending.run.Command(), Host: hostname(), Cwd: safeUnlessEmpty(pending.run.Cwd),
		Caller: safeComposed(pending.run.Caller),
		// Only when it says something the command does not: a relative argv[0]
		// resolves against the request's cwd, so `bin/ansible-playbook` can be a
		// file the agent wrote.
		Program: safeUnlessEmpty(pending.run.resolvedProgram()), LogID: pending.run.LogID,
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
	if s.waiting != nil || s.finishedLocked(awaitLogID) != nil {
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
				other+"), which shares the executor's uid and could ride the escalation")
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
	code, reason := CodeDenied, "refused by "+who
	if approve {
		code, reason = CodeApproved, "approved by "+who
	}
	// Not recorded here: the answer reaches every request waiting on it through
	// `reason`, and each of those writes a record naming who answered.
	log.Printf("escalation: %s %s by %s", id,
		map[bool]string{true: "approved", false: "refused"}[approve], who)
	s.finish(pending, approve, code, reason)
	return nil
}

// ErrNotQuiescent is what a yes becomes when the host was not quiet enough to
// take it. Exported so the broker can give it an error code of its own,
// distinct from an id that had expired.
var ErrNotQuiescent = errors.New("the host was not quiet, so this was refused rather than approved")

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
	s.finish(pending, false, CodeNotQuiescent, "refused: the host was not quiet when this was "+
		"answered ("+detail+")")
	return fmt.Errorf("%w: %s. The sudo waiting on %s has been refused and the "+
		"question is closed. Run the command again once the host is quiet",
		ErrNotQuiescent, detail, id)
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
	return nil, fmt.Errorf("no question %s is waiting; it may have been answered "+
		"already, or its command may have given up", id)
}

// Stop releases everything waiting and refuses anything later: a question
// nobody can answer any more is one sudo would otherwise sit on until its own
// timeout.
func (s *Server) Stop() {
	s.mu.Lock()
	s.stopped = true
	clear(s.runs)
	pending := s.waiting
	s.mu.Unlock()
	if pending != nil {
		// Outside the lock: finish takes it.
		s.finish(pending, false, CodeBrokerStopped, "the broker stopped before this was answered")
	}
}
