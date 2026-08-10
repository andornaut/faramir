package elevate

import (
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

// baseConfig is an enabled elevation with nothing announcing a question: the
// tests answer through the same channel `faramir approve` does.
func baseConfig() config.ElevateConfig {
	return config.ElevateConfig{
		ExecUser:   "faramir-exec",
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-approve",
		TimeoutSec: 10,
	}
}

func started(t *testing.T, cfg config.ElevateConfig) *Server {
	t.Helper()
	s := New(cfg)
	t.Cleanup(s.Stop)
	return s
}

func run() Run {
	return Run{Argv: []string{"ansible-playbook", "msmtp.yml"}, Cwd: "/srv/ctrl", LogID: "log-1"}
}

// mustRegister is Register for the tests that expect the host to be quiet: it
// asserts the run was not held, which the serialization only does while another
// command holds an approved elevation.  The tests that exercise the hold call
// Register directly.
func mustRegister(s *Server, r Run) string {
	token, held := s.Register(r)
	if held {
		panic("a run was held with no approval live")
	}
	return token
}

// human stands in for somebody at `faramir approve --watch`: it answers each
// question as it appears and keeps them, so a test can assert how many were put
// rather than how many sudos ran.
type human struct {
	mu      sync.Mutex
	asked   []Question
	stopped chan struct{}
}

func watching(t *testing.T, s *Server, approve bool) *human {
	t.Helper()
	h := &human{stopped: make(chan struct{})}
	done := make(chan struct{})
	// Before the server's own cleanup, which runs after this one: a watcher
	// polling a stopped server would answer nothing and never return.
	t.Cleanup(func() {
		close(done)
		<-h.stopped
	})
	go func() {
		defer close(h.stopped)
		for {
			select {
			case <-done:
				return
			default:
			}
			for _, question := range s.QuestionsWait(50 * time.Millisecond) {
				h.mu.Lock()
				h.asked = append(h.asked, question)
				h.mu.Unlock()
				_ = s.Answer(question.ID, approve, "the test")
			}
		}
	}()
	return h
}

// questions is how many times a human was put to the question.
func (h *human) questions() int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.asked)
}

func (h *human) prompts() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	var out strings.Builder
	for _, question := range h.asked {
		out.WriteString(question.Prompt + "\n")
	}
	return out.String()
}

// -- disabled by default ----------------------------------------------------

// With no exec_user nothing is granted and nothing is injected, which is the
// install that never passed --elevate.
func TestNoExecUserMeansNothingToAsk(t *testing.T) {
	cfg := baseConfig()
	cfg.ExecUser = ""
	s := started(t, cfg)
	if s.Enabled() {
		t.Error("Enabled with no exec_user")
	}
	if token := mustRegister(s, run()); token != "" {
		t.Errorf("Register returned %q where nothing is granted", token)
	}
	if env := s.Env("anything"); len(env) != 0 {
		t.Errorf("Env = %v, want empty", env)
	}
	if approved, _ := s.Ask("anything"); approved {
		t.Error("an elevation was approved on a host that grants none")
	}
}

// -- the round trip ---------------------------------------------------------

// An approved request says yes, and the human was told which command it was
// for.
func TestAnApprovedRequestIsAllowed(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)

	token := mustRegister(s, run())
	if token == "" {
		t.Fatal("Register returned no token")
	}
	approved, reason := s.Ask(token)
	if !approved {
		t.Fatalf("Ask = false (%s), want approved", reason)
	}
	// The whole argument for this feature is in the question: an approval that
	// names no command is one nobody can judge.
	for _, want := range []string{"ansible-playbook msmtp.yml", "/srv/ctrl", "root"} {
		if !strings.Contains(h.prompts(), want) {
			t.Errorf("the human was asked %q, which does not mention %q", h.prompts(), want)
		}
	}
}

// A refusal reaches the request as a no, and names who gave it, so sudo's
// failure has a reason an operator can find.
func TestARefusedRequestIsDenied(t *testing.T) {
	s := started(t, baseConfig())
	watching(t, s, false)

	approved, reason := s.Ask(mustRegister(s, run()))
	if approved {
		t.Fatal("a refused request was approved")
	}
	if !strings.Contains(reason, "refused by the test") {
		t.Errorf("reason = %q, want the answer to name who gave it", reason)
	}
}

// A request the broker cannot attribute to a running command is refused without
// asking anybody: the question would name nothing, and an approval that names
// nothing is worth nothing.  This is what a `sudo` typed by hand as the
// executor's account looks like.
func TestAnUnknownTokenIsRefusedWithoutAsking(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	// Registered and then finished, which is the late request this covers.
	token := mustRegister(s, run())
	s.Release(token)

	if approved, _ := s.Ask(token); approved {
		t.Error("a released token was approved")
	}
	if approved, _ := s.Ask("0123456789abcdef"); approved {
		t.Error("an invented token was approved")
	}
	if h.questions() != 0 {
		t.Errorf("%d questions were put for requests naming no command", h.questions())
	}
}

// One question per brokered command: ansible calls sudo once per become'd task,
// and a question asked twenty times is one nobody reads.
func TestOneApprovalCoversTheRestOfTheCommand(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)

	token := mustRegister(s, run())
	for i := range 5 {
		if approved, reason := s.Ask(token); !approved {
			t.Fatalf("request %d: %s", i, reason)
		}
	}
	if h.questions() != 1 {
		t.Errorf("5 sudos from one command put %d questions, want 1", h.questions())
	}
}

// The approval is scoped to the command, not to a stretch of time: the next
// brokered command is asked about on its own, however soon it starts.  This is
// what a password could not do -- one could be carried from the approved run to
// this one -- and what nothing here can be, there being nothing to carry.
func TestAnotherCommandIsAskedAboutSeparately(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)

	first := mustRegister(s, run())
	if approved, _ := s.Ask(first); !approved {
		t.Fatal("the first command was refused")
	}
	// The first run ends before the next starts, which is what the serialization
	// requires: two brokered commands do not run at once while one holds root.
	s.Release(first)

	second := mustRegister(s, Run{Argv: []string{"rm", "-rf", "/"}, Cwd: "/srv"})
	if approved, _ := s.Ask(second); !approved {
		t.Fatal("the second command was refused")
	}
	if h.questions() != 2 {
		t.Errorf("two commands put %d questions, want one each", h.questions())
	}
	if !strings.Contains(h.prompts(), "rm -rf /") {
		t.Errorf("the human was not told what the second command was: %s", h.prompts())
	}
}

// waitForQuestion blocks until one is queued and returns its id, or fails: the
// requester's Ask runs in a goroutine, so the question appears a moment later.
func waitForQuestion(t *testing.T, s *Server) string {
	t.Helper()
	for range 200 {
		if q := s.Questions(); len(q) > 0 {
			return q[0].ID
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("no question appeared")
	return ""
}

// The serialization, one half: while a run holds an approved elevation and has
// not ended, no other brokered command may start.  They share the executor's
// uid, so a second could read the approved run's token from /proc and spend it
// on the root it was never shown for.  Held, and admitted again once the run
// ends.
func TestAnApprovalHoldsEveryOtherCommand(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, run())

	go s.Ask(first)
	id := waitForQuestion(t, s)
	if err := s.Answer(id, true, "operator"); err != nil {
		t.Fatalf("the first run was the only one, so it should approve: %v", err)
	}
	if _, held := s.Register(Run{Argv: []string{"curl", "evil"}, Cwd: "/tmp"}); !held {
		t.Error("a new command was admitted while an approved elevation was live: it " +
			"could read the approved run's token and ride it")
	}
	s.Release(first)
	if _, held := s.Register(Run{Argv: []string{"curl", "ok"}, Cwd: "/tmp"}); held {
		t.Error("a command was still held after the approved run ended")
	}
}

// The two halves must be decided against the same instant.  Register admits a
// run while no approval is live; Answer approves while no other run is
// registered.  A gap between Answer's sole-occupancy check and its marking the
// run approved is a window a second run starts in and then rides the approval --
// so run many concurrent rounds and assert the two never both happen.  This is
// the regression guard for that race; under -race the unguarded version trips.
func TestAnApprovalAndASecondRunNeverCoexist(t *testing.T) {
	for range 400 {
		s := New(baseConfig())
		first := mustRegister(s, run())
		go s.Ask(first)
		id := waitForQuestion(t, s)

		var wg sync.WaitGroup
		var approveErr error
		var secondHeld bool
		wg.Add(2)
		go func() { defer wg.Done(); approveErr = s.Answer(id, true, "operator") }()
		go func() {
			defer wg.Done()
			_, secondHeld = s.Register(Run{Argv: []string{"curl", "evil"}, Cwd: "/tmp"})
		}()
		wg.Wait()

		if approveErr == nil && !secondHeld {
			t.Fatalf("the first run was approved while a second was admitted: the " +
				"second shares the executor uid and can ride the approval")
		}
		s.Stop()
	}
}

// The other half: a run is not approved while any other brokered command is
// running, because that other command could ride the approval.  Refused without
// answering the question, so the run keeps waiting and the operator retries once
// the host is quiet rather than the sudo failing now.
func TestAnApprovalWaitsForTheHostToBeQuiet(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, run())
	other := mustRegister(s, Run{Argv: []string{"go", "build"}, Cwd: "/src", LogID: "log-2"})

	go s.Ask(first)
	id := waitForQuestion(t, s)
	err := s.Answer(id, true, "operator")
	if err == nil {
		t.Fatal("approved a run while another brokered command was running")
	}
	if !strings.Contains(err.Error(), "go build") {
		t.Errorf("the refusal does not name the command that blocked it: %v", err)
	}
	// Not answered: still waiting, so it can be approved once the host drains.
	if len(s.Questions()) != 1 {
		t.Error("the refused-for-quiet approval answered the question instead of " +
			"leaving it to be retried")
	}
	s.Release(other)
	if err := s.Answer(id, true, "operator"); err != nil {
		t.Fatalf("still refused after the host went quiet: %v", err)
	}
}

// An approval dies with the command it was given for.
func TestAnApprovalDoesNotOutliveItsCommand(t *testing.T) {
	s := started(t, baseConfig())
	watching(t, s, true)

	token := mustRegister(s, run())
	if approved, _ := s.Ask(token); !approved {
		t.Fatal("refused")
	}
	s.Release(token)
	if approved, _ := s.Ask(token); approved {
		t.Error("an approved token was still allowed after its command ended")
	}
}

// A refusal is not remembered either way: it does not approve the run, and it
// does not poison it.
func TestARefusalIsNotCarried(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, false)

	token := mustRegister(s, run())
	for i := range 2 {
		if approved, _ := s.Ask(token); approved {
			t.Fatalf("request %d was approved", i)
		}
	}
	if h.questions() != 2 {
		t.Errorf("two requests after a refusal put %d questions, want one each: a "+
			"no must not stand in for an approval", h.questions())
	}
}

// A question nobody answers is refused rather than held open.
func TestAnUnansweredQuestionExpires(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 1
	s := started(t, cfg)

	approved, reason := s.Ask(mustRegister(s, run()))
	if approved {
		t.Error("a question nobody answered approved an elevation")
	}
	if !strings.Contains(reason, "nobody answered") {
		t.Errorf("reason = %q, want the timeout named", reason)
	}
	if len(s.Questions()) != 0 {
		t.Error("an expired question is still waiting to be answered")
	}
}

// Concurrent requests from one command share its question rather than each
// putting one of their own: a playbook's tasks arrive in a rush.
func TestConcurrentRequestsShareOneQuestion(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	token := mustRegister(s, run())

	var wg sync.WaitGroup
	refused := make(chan string, 3)
	for range 3 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if approved, reason := s.Ask(token); !approved {
				refused <- reason
			}
		}()
	}
	wg.Wait()
	close(refused)
	for reason := range refused {
		t.Errorf("concurrent request refused: %s", reason)
	}
	if h.questions() != 1 {
		t.Errorf("3 concurrent sudos from one command put %d questions, want 1", h.questions())
	}
}

// Every request is recorded, approved or not, and the record names who
// answered: the audit log is where an operator asks what was elevated, what was
// turned down, and by whom.
func TestEveryRequestIsRecorded(t *testing.T) {
	s := started(t, baseConfig())
	var records []map[string]any
	var mu sync.Mutex
	s.Record = func(entry map[string]any) {
		mu.Lock()
		defer mu.Unlock()
		records = append(records, entry)
	}
	watching(t, s, false)

	if approved, _ := s.Ask(mustRegister(s, run())); approved {
		t.Fatal("a refused request was approved")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(records) != 1 {
		t.Fatalf("%d records, want 1", len(records))
	}
	record := records[0]
	if approved, _ := record["approved"].(bool); approved {
		t.Error("a refusal was recorded as approved")
	}
	if record["op"] != "elevate" {
		t.Errorf("op = %v, want elevate", record["op"])
	}
	if record["exec_log_id"] != "log-1" {
		t.Errorf("exec_log_id = %v, want the command's own record", record["exec_log_id"])
	}
	if outcome, _ := record["outcome"].(string); !strings.Contains(outcome, "the test") {
		t.Errorf("outcome = %q, want it to name who answered", outcome)
	}
}

// -- what the child is given -------------------------------------------------

// A token, and nothing else.  It identifies the run rather than authorising it:
// spending it is an op the broker refuses to anything but root, so what the
// child holds cannot be used by the child, kept, or handed to a later command.
func TestTheChildIsGivenATokenAndNothingElse(t *testing.T) {
	s := started(t, baseConfig())
	token := mustRegister(s, run())
	env := s.Env(token)

	if len(env) != 1 || env[TokenEnv] != token {
		t.Errorf("Env = %v, want only %s", env, TokenEnv)
	}
	for name := range env {
		if strings.Contains(strings.ToUpper(name), "PASS") {
			t.Errorf("%s looks like a credential; this design has none", name)
		}
	}
}

// Stop releases everything waiting rather than leaving sudo to sit until its
// own timeout after the broker has gone.
func TestStopReleasesWhatIsWaiting(t *testing.T) {
	s := New(baseConfig())
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, reason := s.Ask(token)
		if approved {
			done <- "approved"
			return
		}
		done <- reason
	}()
	// Let the question reach the queue before pulling it out from under.
	for range 100 {
		if len(s.Questions()) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	s.Stop()

	select {
	case reason := <-done:
		if reason == "approved" {
			t.Error("a request was approved by a stopping broker")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request waiting on a human outlived the broker")
	}
	if token := mustRegister(s, run()); token != "" {
		t.Error("a run was registered after Stop")
	}
}

// A command that ends takes its unanswered question with it.  A question left
// filed would be shown by `faramir approve` and would take a yes for a command
// that is no longer running, and it would hold one of the maxPending slots until
// its own timeout.
func TestReleasingACommandDropsItsUnansweredQuestion(t *testing.T) {
	s := started(t, baseConfig()) // TimeoutSec is 10: nothing here may wait that long
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, reason := s.Ask(token)
		if approved {
			done <- "approved"
			return
		}
		done <- reason
	}()
	id := waitForQuestion(t, s)

	s.Release(token)

	select {
	case reason := <-done:
		if reason == "approved" {
			t.Error("a request was approved after its command ended")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("a request outlived the command it was raised for")
	}
	if left := s.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after the command ended: %v", len(left), left)
	}
	if err := s.Answer(id, true, "the operator"); err == nil {
		t.Error("a question was approved for a command that had already ended")
	}
}

// The two refusals pend can give are told apart.  A saturated host and a
// stopping broker send an operator looking in different places, and one
// reported as the other sends them hunting for pending questions that are not
// there.
func TestARefusalSaysWhichLimitItHit(t *testing.T) {
	s := started(t, baseConfig())
	// Fill the queue: one question per command, so this takes maxPending commands.
	for i := range maxPending {
		token := mustRegister(s, Run{Argv: []string{"playbook", strconv.Itoa(i)}})
		go s.Ask(token)
	}
	for range 100 {
		if len(s.Questions()) == maxPending {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if _, _, reason := s.pend(mustRegister(s, run()), run()); !strings.Contains(reason, "waiting") {
		t.Errorf("reason = %q, want the full queue named", reason)
	}

	// A stopping broker, which Ask reaches when Stop lands between its own lookup
	// and this call.
	stopping := New(baseConfig())
	token := mustRegister(stopping, run())
	stopping.Stop()
	if _, _, reason := stopping.pend(token, run()); !strings.Contains(reason, "stopping") {
		t.Errorf("reason = %q, want the stopping broker named rather than a full queue", reason)
	}
}

// -- the answer channel ------------------------------------------------------

// Answering a question nobody is waiting on is an error rather than a silent
// success: the operator has typed an id that has expired, and needs to know.
func TestAnsweringAnUnknownQuestionFails(t *testing.T) {
	s := started(t, baseConfig())
	if err := s.Answer("beef00", true, "the test"); err == nil {
		t.Error("answering a question nobody asked succeeded")
	}
}

// A watcher blocks until there is something to answer rather than polling, and
// gives up on its own clock so a broker that went away is noticed.
func TestQuestionsWaitBlocksUntilSomethingIsAsked(t *testing.T) {
	s := started(t, baseConfig())

	if got := s.QuestionsWait(50 * time.Millisecond); len(got) != 0 {
		t.Errorf("QuestionsWait = %v with nothing waiting", got)
	}
	token := mustRegister(s, run())
	go func() { _, _ = s.Ask(token) }()

	questions := s.QuestionsWait(5 * time.Second)
	if len(questions) != 1 {
		t.Fatalf("QuestionsWait returned %d questions, want the one just asked", len(questions))
	}
	question := questions[0]
	if question.ID == "" || question.Prompt == "" {
		t.Errorf("a question with nothing to show: %+v", question)
	}
	if question.Cmd != "ansible-playbook msmtp.yml" {
		t.Errorf("cmd = %q, want the command being asked about", question.Cmd)
	}
}
