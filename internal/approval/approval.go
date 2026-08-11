// Package approval lets a brokered command become root on this host, once, with
// a human's consent, and holds no credential that could do it again.  Why it is
// shaped this way is docs/design.md; this is what the code must maintain.
//
//   - The child's environment carries FARAMIR_APPROVAL_TOKEN and nothing else.
//     Inert on its own: the op that spends it is refused to anything but root.
//   - The PAM helper finds the token by walking /proc up from sudo, so nothing
//     has to be threaded through PAM, and asks the broker over its socket.
//   - The broker files a question, a human answers it through `faramir
//     approve`, and the answer releases every request from that one command.
//
// Optional: with no [sudo] exec_user nothing is granted and no question can be
// raised.
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"
	"unicode/utf8"

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
// question names, and naming it is what makes the answer worth anything: an
// approval the human cannot attribute to a command they initiated grants root
// to whatever asked.
type Run struct {
	// Argv is the command the broker started, already redacted: a caller can put
	// a value in argv even though the broker never does, and this reaches a
	// terminal and the audit log.
	Argv []string
	Cwd  string
	// Argv0Path is what the broker resolved Argv[0] to, and so the program root
	// will actually run.  A relative Argv[0] resolves against the request's cwd,
	// which is the agent's working tree, so the two can name different files and
	// the question has to say which one it is about.
	Argv0Path string
	// LogID is the exec record this belongs to, so the log reads in both
	// directions: what a command was approved for, and what an approval was spent on.
	LogID string

	// approved is set once a human has said yes to this run, and is what makes
	// the rest of its sudos free of a second question.  Not exported: a caller
	// registering a run pre-approved would be an approval nobody answered.
	approved bool
}

// maxCommandChars bounds what a question spends on the command.  Argv is the
// caller's and can be as long as it likes; a question whose real content has
// scrolled off the top of a terminal is one nobody read.  The audit record keeps
// the whole of it.
const maxCommandChars = 240

// Command is the run as one line, rendered for a terminal.
//
// Every string in it is the caller's, and this reaches the operator's terminal
// through `faramir approve`, the refusal messages and [sudo] notify_command.  A
// terminal acts on what it is sent: "\r" returns the cursor, ESC [ 2K erases the
// line, ESC [ A moves up one.  Left raw, a run could erase the question it is
// being judged on and paint a more agreeable one in its place -- which would
// defeat the only thing that makes an approval worth anything, that the prompt
// names the command.  So each argument is quoted the moment it holds anything
// but printable text, and the whole is bounded.
func (r Run) Command() string {
	parts := make([]string, 0, len(r.Argv))
	for _, arg := range r.Argv {
		parts = append(parts, safeArg(arg))
	}
	return bound(strings.Join(parts, " "), maxCommandChars)
}

// safeArg renders one caller-chosen string so a terminal displays it rather than
// obeying it.  Ordinary arguments are left alone -- a prompt full of quotation
// marks is one that is read less carefully -- and anything holding a control
// character, a space, a quote or a non-printable rune is quoted, which turns
// every such byte into a visible escape.
func safeArg(arg string) string {
	if arg == "" {
		return `""`
	}
	if strconv.Quote(arg) == `"`+arg+`"` && !strings.ContainsAny(arg, " \t") {
		return arg
	}
	return strconv.Quote(arg)
}

// safeUnlessEmpty is safeArg for a field a caller drops when it is absent.
func safeUnlessEmpty(value string) string {
	if value == "" {
		return ""
	}
	return safeArg(value)
}

// bound truncates on a rune boundary and says that it did.  Silent truncation
// would let a long argv end the displayed command wherever it liked.
func bound(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	cut := text[:limit]
	for len(cut) > 0 && !utf8.ValidString(cut) {
		cut = cut[:len(cut)-1]
	}
	return fmt.Sprintf("%s... (%d more bytes; the audit record has all of it)",
		cut, len(text)-len(cut))
}

type Server struct {
	config config.SudoConfig

	// Record writes one audit entry per request.  Set by the broker; nil records
	// nothing, which is the case in tests.
	Record func(map[string]any)

	// Quiescent asks the kernel what this server only believes: is any process of
	// the executor's uid alive outside the runs this server knows about?
	//
	// Everything else here is bookkeeping, and bookkeeping is what an approval
	// must not rest on alone.  /proc/<pid>/environ is readable within a uid, so
	// any live executor-uid process during an approved window can read the
	// approved run's token, exec with it set and sudo on it -- which means the
	// map below has to agree with the process table, and three things can part
	// them: a cgroup teardown that does not finish (the drain is bounded and
	// reports by logging), a run aborted from the broker's side, whose teardown
	// the broker does not wait for, and this process restarting, which forgets
	// every run while the executor is still killing one.
	//
	// Set by the broker to a call on the executor, which is the only account that
	// can see those processes at all: the broker's own unit sets
	// ProtectProc=invisible, so another uid's /proc is not there to read.  Nil
	// means unchecked, which is the case in tests; in production an unset or
	// unreachable check refuses the approval.
	Quiescent func() (quiet bool, detail string)

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
// never shown for.  A held command must not run: the broker turns it into a
// `busy` the caller retries once the approved run ends.  This is one half of a
// symmetry: registering a run also blocks a *new* approval (Answer requires sole
// occupancy), so a live approval and any other registered run never coexist.
//
// A question merely *pending* holds a new command too, and that is not the same
// rule twice.  Answer refuses to approve while any other run is registered, so
// a caller free to keep starting commands is a caller who decides whether the
// host is ever quiet enough for a yes to take: the operator answers, is refused
// for want of quiescence, and answers again.  Holding from the moment the
// question is put makes the host drain toward the answer instead of away from
// it.  The cost is that one unanswered question stalls unrelated brokered work
// for up to [sudo] timeout_sec, which is the same cost an approved run already
// imposes for its whole length.
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
	if why := s.holdLocked(); why != "" {
		log.Printf("approval: holding a new command: %s", why)
		return "", true
	}
	s.runs[token] = run
	return token, false
}

// holdLocked says why a new brokered command may not start now, or "".
func (s *Server) holdLocked() string {
	if approved := s.approvalLiveLocked(); approved != "" {
		return fmt.Sprintf("%s holds an approval", approved)
	}
	for _, pending := range s.waiting {
		return fmt.Sprintf("%s is waiting to be approved", pending.run.Command())
	}
	return ""
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
// by the tenth.  That is not sudo's timestamp by another name: a timestamp is a
// stretch of time, and anything starting a command inside it rides an approval
// given for something else.  This is scoped to the command the human
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
	id := newID()
	if id == "" {
		return nil, false, "this question could not be named, so nothing could answer it"
	}
	pending := &approval{
		id: id, token: token, run: run, asked: time.Now(),
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
// runs (wall, a desktop notifier, a push) cannot approve anything: the
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
//
// Empty when there is no randomness, and the caller refuses the request rather
// than substituting a constant: two questions sharing an id are two questions
// Answer picks between by map order, which is to say at random.  A question that
// cannot be named is one nobody can answer on purpose.
func newID() string {
	var raw [3]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return ""
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
// Every caller-chosen part of it is rendered through safeArg, for the reason
// given on Command: this string is printed to a terminal, and a terminal obeys
// escape sequences.
func Prompt(run Run) string {
	host, err := os.Hostname()
	if err != nil || host == "" {
		host = "this host"
	}
	where := ""
	if run.Cwd != "" {
		where = " in " + safeArg(run.Cwd)
	}
	// Named only when it is not what the command says, which is the case worth a
	// human's attention: a relative argv[0] resolves against the request's cwd,
	// so `bin/ansible-playbook` can be a file the agent wrote.  Saying it every
	// time would make the line longer and the difference harder to notice.
	program := ""
	if len(run.Argv) > 0 && run.Argv0Path != "" && run.Argv0Path != run.Argv[0] {
		program = " (which is " + safeArg(run.Argv0Path) + ")"
	}
	return fmt.Sprintf("faramir: run as root on %s: %s%s%s -- approve every sudo "+
		"this command makes until it ends? Type yes", host, run.Command(), program, where)
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
	// Program is what argv[0] resolved to, and so what root will run.  Shown
	// separately from Cmd because they can differ: a relative argv[0] resolves
	// against the request's cwd, which the agent writes.
	Program string `json:"program"`
	LogID   string `json:"log_id"`
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
			// Rendered like the command, and for the same reason: these are the
			// caller's strings and they are printed to a terminal.  Absent stays
			// absent -- safeArg would render "" as a pair of quotation marks, which
			// the caller would then print as a field holding nothing.
			Cmd: pending.run.Command(), Cwd: safeUnlessEmpty(pending.run.Cwd),
			Program: safeUnlessEmpty(pending.run.Argv0Path), LogID: pending.run.LogID,
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
	if _, err := s.find(id); err != nil {
		return err
	}
	// Outside the lock, and before it: the check is a round trip to the executor.
	//
	// Checking first and locking after is sound, and worth saying why.  A process
	// that appeared between the two would have to have been spawned by something
	// already running -- which this check would have seen -- or by the run being
	// approved, which is what the approval is for; and a new *run* starting in
	// that gap is caught by the sole-occupancy check below, under the lock.
	if approve {
		if s.Quiescent == nil {
			log.Printf("approval: %s has no quiescence check, so it is approved on "+
				"this server's own bookkeeping alone", id)
		} else if quiet, detail := s.Quiescent(); !quiet {
			return fmt.Errorf("not approving %s: %s. Every process on the executor's "+
				"uid can read this run's token and sudo on it, so the host has to be "+
				"quiet before a yes takes. Retry once it is", id, detail)
		}
	}

	s.mu.Lock()
	pending, err := s.findLocked(id)
	if err != nil {
		s.mu.Unlock()
		return err
	}
	// Sole occupancy: root is handed to a run only when it is the one brokered
	// command running.  Anything else on the executor's uid could read this run's
	// token and ride the approval, so the host has to be quiet before a yes takes.
	// Refused without answering the question, so the run keeps waiting and the
	// operator retries once the others drain, rather than this sudo failing now
	// and the run having to ask again.  A refusal (no) needs no such quiet.
	//
	// The check and the flag it stands on are set under one lock hold, on purpose:
	// Register admits a new run whenever no approval is live, so a gap between "no
	// other run is registered" and "this run is marked approved" is a window in
	// which a second command starts and then rides this approval.  Marking it here,
	// still holding mu, is what closes that window; finish only carries the
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

// find is findLocked for a caller that does not hold the lock.
func (s *Server) find(id string) (*approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.findLocked(id)
}

// findLocked is the question with this id, or why there is none.
func (s *Server) findLocked(id string) (*approval, error) {
	for _, candidate := range s.waiting {
		if candidate.id == id {
			return candidate, nil
		}
	}
	return nil, fmt.Errorf("no question %s is waiting; it may have been answered "+
		"already, or its command may have given up", id)
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
