// Package approval lets a brokered command become root on this host, once, with
// a human's consent, and holds no credential that could do it again.
//
// `faramir init --allow-sudo` grants the executor's uid a sudoers entry and points
// sudo at a PAM service of faramir's own, whose whole authentication step is a
// helper that asks the broker whether this command was approved.  There is no
// password: nothing is minted, nothing is stored, nothing is handed out, and so
// nothing can be kept.  The broker's answer is the credential, it is spent
// where it is given, and it names one command.
//
// What that fixes.  A password is a bearer token: whatever holds it can
// authenticate, so a command approved once could read the value out of the
// helper it was given and leave it for a later brokered command that was never
// approved -- same uid, shared PrivateTmp, shared working tree.  One approval
// became root until the value was replaced.  An approval that is a decision
// rather than a secret cannot be carried anywhere.
//
// How the pieces fit:
//
//   - The child's environment carries FARAMIR_APPROVAL_TOKEN and nothing else.
//     Inert on its own: the op that spends it is refused to anything but root.
//   - sudo runs the PAM helper as root (pam_exec's `seteuid`; without it the
//     helper runs as the *invoking* uid, which is the child's own, and the
//     child is its ancestor and could ptrace it into exiting zero).
//   - The helper finds the token by walking /proc up from sudo, so nothing has
//     to be threaded through PAM, and asks the broker over the broker socket.
//   - The broker files a question, a human answers it through `faramir
//     approve`, and the answer releases every request from that one command.
//
// The bound this does not reach, and no design here can: an approved command
// *is* root, and root can remove the gate -- write its own sudoers file, edit
// the PAM service, replace the helper.  An approval is consent for a command,
// not a sandbox around it.
//
// Optional: with no [sudo] exec_user nothing is granted, no question can be
// raised, and a brokered command's sudo fails as it does on any host that
// granted nothing.
package approval

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
)

const (
	// How many commands may be waiting on a human at one time.  Requests from one
	// command share a question, so this counts commands rather than sudos.  Beyond
	// it a request is refused, which sudo reports as a failed authentication
	// rather than hanging.
	maxPending = 4
	// How long the notifier may run before it is killed.  It announces a pending
	// question and returns nothing, so nothing waits on it.
	notifyTimeout = 10 * time.Second
	// TokenEnv is how a brokered command's descendants name the run they belong
	// to.  The helper reads it out of /proc rather than being passed it, because
	// PAM does not carry the child's environment into the module.
	//
	// The value is the name of an environment variable, not a credential: what it
	// names identifies a run, and the op that spends it is refused to anything but
	// root.  gosec keys G101 off the "TOKEN" in the identifier, hence the exception.
	TokenEnv = "FARAMIR_APPROVAL_TOKEN" //nolint:gosec // G101: env var name, not a credential
)

// Run is the brokered command a request is made on behalf of.  It is what the
// question names, and naming it is what makes the answer worth anything: a
// human who approves an approval they did not initiate has already lost.
type Run struct {
	// Argv is the command the broker started, already redacted: a caller can put
	// a value in argv even though the broker never does, and this reaches a
	// terminal and the audit log.
	Argv []string
	Cwd  string
	// LogID is the exec record this belongs to, so the log reads in both
	// directions: what a command was approved for, and what an approval was spent on.
	LogID string

	// approved is set once a human has said yes to this run, and is what makes
	// the rest of its sudos free of a second question.  Not exported: a caller
	// registering a run pre-approved would be an approval nobody answered.
	approved bool
}

// Command is the run as one line, for the question and for a log message.
func (r Run) Command() string { return strings.Join(r.Argv, " ") }

type Server struct {
	config config.SudoConfig

	// Record writes one audit entry per request.  Set by the broker; nil records
	// nothing, which is the case in tests.
	Record func(map[string]any)

	mu sync.Mutex
	// runs is what is in flight, keyed by the token in each child's environment.
	runs map[string]Run
	// waiting is the questions a human has not answered yet, one per command
	// rather than one per sudo.  Keyed by token, so the second task of a playbook
	// joins the question the first one raised instead of asking again.
	waiting map[string]*approval
	// changed is closed and replaced whenever waiting does, so `faramir approve
	// --watch` can block on the next change rather than poll for it.
	changed chan struct{}
	stopped bool
}

// approval is one unanswered question.  Every request for the same command
// waits on the same one.
type approval struct {
	id    string
	token string
	run   Run
	asked time.Time

	// done is closed once answered, expired or dropped; the fields above it are
	// written before the close and read after, so the channel is the barrier.
	done     chan struct{}
	once     sync.Once
	approved bool
	reason   string
}

func New(cfg config.SudoConfig) *Server {
	return &Server{
		config:  cfg,
		runs:    map[string]Run{},
		waiting: map[string]*approval{},
		changed: make(chan struct{}),
	}
}

// Enabled reports whether this host granted the executor anything to ask about.
// exec_user names the account the sudoers entry was written for, so its absence
// is an install that never passed --allow-sudo.
func (s *Server) Enabled() bool { return s.config.ExecUser != "" }

// Env is what to add to a child's environment: a token, and nothing else.
//
// Inert in the child's hands.  Spending it means the `ask_approval` op, which the
// broker refuses to anything but root, so the token identifies a run rather
// than authorising one.
func (s *Server) Env(token string) map[string]string {
	if !s.Enabled() || token == "" {
		return map[string]string{}
	}
	return map[string]string{TokenEnv: token}
}

// Register records the command a token stands for and returns the token.  Empty
// where nothing is granted, which Env reads as nothing to inject.
//
// held is the serialization, and the reason an approval is safe on a host that
// runs other agent work.  While one command holds an approval, no
// other brokered command may start: they share the executor's uid, so a second
// process could read the first's token out of /proc and ride the approval it was
// never shown for.  A held command must not run -- the broker turns it into a
// `busy` the caller retries once the approved run ends.  This is one half of a
// symmetry: registering a run also blocks a *new* approval (Answer requires sole
// occupancy), so a live approval and any other registered run never coexist.
func (s *Server) Register(run Run) (token string, held bool) {
	if !s.Enabled() {
		return "", false
	}
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		// Without a token the broker cannot say what it is approving, and an
		// unnamed approval is the thing this exists to avoid.
		log.Printf("approval: no randomness for a token (%v); this command cannot sudo", err)
		return "", false
	}
	token = hex.EncodeToString(raw[:])
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.stopped {
		return "", false
	}
	if approved := s.approvalLiveLocked(); approved != "" {
		log.Printf("approval: holding a new command while %q holds an approval", approved)
		return "", true
	}
	s.runs[token] = run
	return token, false
}

// approvalLiveLocked names the command whose approval currently holds the host,
// or "".  At most one is ever live: approving requires sole occupancy and a live
// approval holds every new run, so a second can never be approved while the
// first still runs.
func (s *Server) approvalLiveLocked() string {
	for _, run := range s.runs {
		if run.approved {
			return run.Command()
		}
	}
	return ""
}

// otherRunLocked names a registered run whose token is not the given one, or
// "".  That is precisely what an approval would let ride: a second process on
// the executor's uid, in flight while root is handed out.
func (s *Server) otherRunLocked(token string) string {
	for t, run := range s.runs {
		if t != token {
			return run.Command()
		}
	}
	return ""
}

// Release drops a token when its command ends, so a request that arrives after
// is refused rather than answered against a command that is over.  This is what
// makes an approval die with the run it was given for.
//
// The command's unanswered question goes with it.  One left filed would be shown
// by `faramir approve` and would take a yes for a command that is no longer
// running, which is an approval a human cannot judge, and it would hold one of
// the maxPending slots until it timed out.
func (s *Server) Release(token string) {
	if token == "" {
		return
	}
	s.mu.Lock()
	delete(s.runs, token)
	pending := s.waiting[token]
	s.mu.Unlock()
	if pending != nil {
		// Outside the lock: finish takes it.
		s.finish(pending, false, "the command ended before this was answered")
	}
}

// Ask is the whole of what a sudo asks for: may this command become root?
//
// It blocks until a human answers, the question expires, or the broker stops.
// The caller is the PAM helper's request, which the broker has already checked
// came from root; sudo is blocked on it, which is what makes the wait a
// password prompt from sudo's point of view.
func (s *Server) Ask(token string) (approved bool, reason string) {
	if !s.Enabled() {
		return false, "this host grants no approval"
	}
	s.mu.Lock()
	run, known := s.runs[token]
	s.mu.Unlock()
	if !known {
		// Refused rather than asked about: without the token the broker cannot say
		// what it would be approving, and an approval that names no command is
		// one a human cannot judge.  This is what a request from outside a brokered
		// command, or after one ended, looks like.
		log.Printf("approval: refusing a request whose token names no running command")
		s.record(map[string]any{
			"log_id": audit.NewLogID(), "op": "ask_approval", "approved": false,
			"outcome": "the token named no running command",
		})
		return false, "this request names no brokered command, so there is nothing to approve"
	}

	approved, prompted, reason := s.ask(token, run)
	s.record(map[string]any{
		"log_id": audit.NewLogID(), "op": "ask_approval", "approved": approved,
		"prompted": prompted, "cmd": run.Argv, "cwd": run.Cwd,
		"exec_log_id": run.LogID, "outcome": reason,
	})
	if !approved {
		log.Printf("approval: %q was not approved: %s", run.Command(), reason)
	}
	return approved, reason
}

// ask reports whether this request may sudo, and whether it was the one that
// put the question.
//
// One question per brokered command, not per sudo: ansible-playbook calls sudo
// once per become'd task, and a question asked twenty times is one nobody reads
// by the tenth.  That is not sudo's timestamp by another name -- a timestamp is
// a stretch of time, and anything starting a command inside it rides an
// approval given for something else.  This is scoped to the command the human
// was shown, dies when the run ends, and cannot be reached by a second run.
func (s *Server) ask(token string, run Run) (approved, prompted bool, reason string) {
	pending, raised, refused := s.pend(token, run)
	if pending == nil {
		return false, false, refused
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
	return pending.approved, raised, pending.reason
}

// pend files the question, or hands back the one this command already raised.
// The second return is whether this call is the one that raised it; the third is
// why no question could be filed, when none was.  The two refusals are reported
// apart: a saturated host and a stopping broker send an operator looking in
// different places.
func (s *Server) pend(token string, run Run) (*approval, bool, string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	// Re-checked under the lock: the requests of a playbook arrive in a rush, and
	// one that read "not approved" outside it may have been overtaken.
	if s.runs[token].approved {
		answered := &approval{done: make(chan struct{}), approved: true,
			reason: "covered by the approval given for this command"}
		close(answered.done)
		return answered, false, ""
	}
	if existing, ok := s.waiting[token]; ok {
		return existing, false, ""
	}
	if s.stopped {
		return nil, false, "the broker is stopping, so nothing can be approved now"
	}
	if len(s.waiting) >= maxPending {
		return nil, false, fmt.Sprintf(
			"%d commands are already waiting to be approved", maxPending)
	}
	pending := &approval{
		id: newID(), token: token, run: run, asked: time.Now(),
		done: make(chan struct{}),
	}
	s.waiting[token] = pending
	s.wakeLocked()
	log.Printf("approval: %s is waiting to be approved: %s", pending.id, run.Command())
	return pending, true, ""
}

// finish answers a question once, releasing every request waiting on it.
//
// It does not set the run's approved flag: Answer does that under the same lock
// as its sole-occupancy check, because a gap between the two is a window a second
// run could start in and ride the approval.  finish only carries the answer to
// the sudos blocked on this question.  (expire and Stop reach here too, always
// with approved=false, which touches no run.)
func (s *Server) finish(pending *approval, approved bool, reason string) {
	pending.once.Do(func() {
		s.mu.Lock()
		pending.approved, pending.reason = approved, reason
		// Only if it is still the current question for that command: a token
		// released and re-registered would otherwise lose its own.
		if s.waiting[pending.token] == pending {
			delete(s.waiting, pending.token)
		}
		s.wakeLocked()
		s.mu.Unlock()
		close(pending.done)
	})
}

// expire drops a question nobody answered.  Deny by default: silence is a no,
// and a request that waited is one sudo has been sitting on.
func (s *Server) expire(pending *approval) {
	timer := time.NewTimer(time.Duration(s.config.TimeoutSec) * time.Second)
	defer timer.Stop()
	select {
	case <-pending.done:
	case <-timer.C:
		s.finish(pending, false, fmt.Sprintf("nobody answered within %ds", s.config.TimeoutSec))
	}
}

// wakeLocked releases everything blocked on the next change.  Called with the
// lock held.
func (s *Server) wakeLocked() {
	close(s.changed)
	s.changed = make(chan struct{})
}

// notify announces a pending question, and reads nothing back.  Whatever it
// runs -- wall, a desktop notifier, a push -- cannot approve anything: the
// answer comes over the broker socket from a caller SO_PEERCRED says is root.
func (s *Server) notify(pending *approval) {
	if len(s.config.NotifyCommand) == 0 {
		return
	}
	argv := make([]string, 0, len(s.config.NotifyCommand))
	for _, arg := range s.config.NotifyCommand {
		arg = strings.ReplaceAll(arg, "{prompt}", Prompt(pending.run))
		argv = append(argv, strings.ReplaceAll(arg, "{id}", pending.id))
	}
	// The deadline is the context's, and the kill runs from inside cmd.Wait: a
	// timeout that signalled from a goroutine of its own could fire after the
	// process had been reaped, and the kernel reuses a pid once nothing holds it,
	// so the signal would reach some unrelated process group of the broker's uid.
	// Wait has not returned while Cancel runs, so the pid is still this notifier's.
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
		log.Printf("approval: cannot run the notifier %s: %v", argv[0], err)
		return
	}
	go func() {
		defer cancel()
		_ = cmd.Wait()
	}()
}

// newID names a question in something a person can type.  Short: it is read off
// one terminal and typed into another, and it names a question that lives for
// seconds among at most maxPending of them.
func newID() string {
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "000000"
	}
	return hex.EncodeToString(raw[:])
}

// Prompt is what the human is asked.  Exported so a test, the CLI and the
// README can agree on it, and because it is the whole security argument in one
// line: the command is named, so the answer means something.
//
// It says what the answer covers, too.  A yes is spent on every sudo this one
// command makes, so a question that read as though it covered a single task
// would be asking for something other than what it grants.
func Prompt(run Run) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "this host"
	}
	where := ""
	if run.Cwd != "" {
		where = " in " + run.Cwd
	}
	return fmt.Sprintf("faramir: run as root on %s: %s%s -- approve every sudo "+
		"this command makes until it ends? Type yes", host, run.Command(), where)
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
	Cwd    string `json:"cwd"`
	LogID  string `json:"log_id"`
	// WaitingSec says how long sudo has been sitting on this, so an operator can
	// tell a question just raised from one about to expire.
	WaitingSec int `json:"waiting_sec"`
}

// Questions is what is waiting now, longest first.
func (s *Server) Questions() []Question {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.questionsLocked()
}

func (s *Server) questionsLocked() []Question {
	out := make([]Question, 0, len(s.waiting))
	for _, pending := range s.waiting {
		out = append(out, Question{
			ID: pending.id, Prompt: Prompt(pending.run),
			Cmd: pending.run.Command(), Cwd: pending.run.Cwd, LogID: pending.run.LogID,
			WaitingSec: int(time.Since(pending.asked).Seconds()),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].WaitingSec > out[j].WaitingSec })
	return out
}

// QuestionsWait is Questions for a watcher: it returns at once if anything is
// waiting, and otherwise blocks until something is or the wait runs out.  A
// long poll rather than a subscription, because the caller is a person with a
// terminal and the broker keeps no client state.
func (s *Server) QuestionsWait(wait time.Duration) []Question {
	s.mu.Lock()
	if len(s.waiting) > 0 {
		defer s.mu.Unlock()
		return s.questionsLocked()
	}
	changed := s.changed
	s.mu.Unlock()

	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case <-changed:
	case <-timer.C:
	}
	return s.Questions()
}

// Answer decides one question.  The caller is checked to be root before this is
// reached: it is the whole boundary, since the account the coding agent runs as
// must not be able to approve what the agent asked for.
func (s *Server) Answer(id string, approve bool, who string) error {
	s.mu.Lock()
	var pending *approval
	for _, candidate := range s.waiting {
		if candidate.id == id {
			pending = candidate
			break
		}
	}
	if pending == nil {
		s.mu.Unlock()
		return fmt.Errorf("no question %s is waiting; it may have been answered "+
			"already, or its command may have given up", id)
	}
	// Sole occupancy: root is handed to a run only when it is the one brokered
	// command running.  Anything else on the executor's uid could read this run's
	// token and ride the approval, so the host has to be quiet before a yes takes.
	// Refused without answering the question, so the run keeps waiting and the
	// operator retries once the others drain -- rather than this sudo failing now
	// and the run having to ask again.  A refusal (no) needs no such quiet.
	//
	// The check and the flag it stands on are set under one lock hold, on purpose:
	// Register admits a new run whenever no approval is live, so a gap between "no
	// other run is registered" and "this run is marked approved" is a window in
	// which a second command starts and then rides this approval.  Marking it here,
	// still holding mu, is what closes that window -- finish only carries the
	// answer to the waiters.
	if approve {
		if other := s.otherRunLocked(pending.token); other != "" {
			s.mu.Unlock()
			return fmt.Errorf("not approving %s while another brokered command runs "+
				"(%s): it shares the executor's uid and could ride the approval. Retry "+
				"once the host is quiet", id, other)
		}
		if run, ok := s.runs[pending.token]; ok {
			run.approved = true
			s.runs[pending.token] = run
		}
	}
	s.mu.Unlock()
	reason := "refused by " + who
	if approve {
		reason = "approved by " + who
	}
	// Not recorded here: the answer reaches every request waiting on it through
	// `reason`, and each of those writes a record naming who answered.  One
	// record per sudo, so the log says how many the approval covered rather than
	// leaving it to be counted.
	log.Printf("approval: %s %s by %s", id,
		map[bool]string{true: "approved", false: "refused"}[approve], who)
	s.finish(pending, approve, reason)
	return nil
}

// Stop releases everything waiting and refuses anything later.  A question
// nobody can answer any more is one sudo would otherwise sit on until its own
// timeout, after the broker has already gone.
func (s *Server) Stop() {
	s.mu.Lock()
	s.stopped = true
	clear(s.runs)
	waiting := make([]*approval, 0, len(s.waiting))
	for _, pending := range s.waiting {
		waiting = append(waiting, pending)
	}
	s.mu.Unlock()
	// Outside the lock: finish takes it.
	for _, pending := range waiting {
		s.finish(pending, false, "the broker stopped before this was answered")
	}
}
