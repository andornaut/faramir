package escalation

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

// baseConfig is an enabled escalation with nothing announcing a question: the
// tests answer through the same channel `faramir sudo approve` does.
func baseConfig() config.SudoConfig {
	return config.SudoConfig{
		ExecUser:   "faramir-exec",
		PamService: "faramir-sudo",
		Helper:     "/usr/local/libexec/faramir/pam-escalate",
		TimeoutSec: 10,
	}
}

func started(t *testing.T, cfg config.SudoConfig) *Server {
	t.Helper()
	s := New(cfg)
	// A quiet host, which is what these tests are about the other half of. It has
	// to be said rather than left nil: nil refuses every escalation, so that a
	// Server built without a way to ask the kernel grants no root. The tests that
	// are about the check itself set their own.
	s.Quiescent = func() (bool, string) { return true, "the test says so" }
	// The executor's half: which run forked the process that asked. Stubbed from
	// the registry, so a test hands Ask an ancestry the way the PAM helper does
	// and gets back the run it belongs to, the way the executor answers.
	s.Owner = ownerFromRegistry(s)
	t.Cleanup(s.Stop)
	return s
}

// pidFor is the process a test's run was forked as. Derived from the run id so
// no test has to carry a second identifier around.
func pidFor(runID string) int {
	sum := 1000
	for _, b := range []byte(runID) {
		sum = sum*31 + int(b)
		sum %= 1 << 20
	}
	return sum + 2
}

// procsFor is the ancestry the PAM helper would send from inside this run: one
// process, which is enough, the walk's length being the helper's business.
func procsFor(runID string) []int {
	return []int{pidFor(runID)}
}

// ownerFromRegistry stands in for the executor: it answers for a run this server
// has registered and for nothing else, which is the property the real one has.
func ownerFromRegistry(s *Server) func([]int) (string, string) {
	return func(ancestors []int) (string, string) {
		s.mu.Lock()
		defer s.mu.Unlock()
		for _, pid := range ancestors {
			for runID := range s.runs {
				if pidFor(runID) == pid {
					return runID, "the test forked it"
				}
			}
		}
		return "", "the test forked none of these"
	}
}

func run() Run {
	return Run{Argv: []string{"ansible-playbook", "msmtp.yml"}, Cwd: "/srv/ctrl", LogID: "log-1"}
}

// mustRegister is Register for the tests that expect the host to be quiet: it
// asserts the run was not held, which the serialization only does while another
// command holds an escalation. The tests that exercise the hold call
// Register directly.
func mustRegister(s *Server, r Run) string {
	token, heldBy := s.Register(r)
	if heldBy != "" {
		panic("a run was held with no escalation live")
	}
	return token
}

// human stands in for somebody at `faramir sudo watch`: it answers each
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
			questions, _ := s.Poll(50*time.Millisecond, "")
			for _, question := range questions {
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

// first is the question the human was put first, for a test reading the fields
// printed under the prompt rather than the prompt line itself.
func (h *human) first(t *testing.T) Question {
	t.Helper()
	h.mu.Lock()
	defer h.mu.Unlock()
	if len(h.asked) == 0 {
		t.Fatal("the human was asked nothing")
	}
	return h.asked[0]
}

// -- disabled by default ----------------------------------------------------

// With no exec_user nothing is granted and no run is named, which is the
// install that never passed --allow-sudo.
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
	if approved, _, _ := s.Ask(procsFor("anything")); approved {
		t.Error("an escalation was approved on a host that grants none")
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
	approved, _, reason := s.Ask(procsFor(token))
	if !approved {
		t.Fatalf("Ask = false (%s), want approved", reason)
	}
	// The whole argument for this feature is in the question: an escalation that
	// names no command is one nobody can judge.
	for _, want := range []string{"ansible-playbook msmtp.yml", "root"} {
		if !strings.Contains(h.prompts(), want) {
			t.Errorf("the human was asked %q, which does not mention %q", h.prompts(), want)
		}
	}
	// Where it would run is a field of the question, printed under the prompt.
	asked := h.first(t)
	if asked.Cwd != "/srv/ctrl" {
		t.Errorf("question.Cwd = %q, want the request's cwd", asked.Cwd)
	}
	if asked.Host == "" {
		t.Error("question.Host is empty; the question names no host to become root on")
	}
}

// A refusal reaches the request as a no, and names who gave it, so sudo's
// failure has a reason an operator can find.
func TestARefusedRequestIsDenied(t *testing.T) {
	s := started(t, baseConfig())
	watching(t, s, false)

	approved, _, reason := s.Ask(procsFor(mustRegister(s, run())))
	if approved {
		t.Fatal("a refused request was approved")
	}
	if !strings.Contains(reason, "rejected by the test") {
		t.Errorf("reason = %q, want the answer to name who gave it", reason)
	}
}

// A request the broker cannot attribute to a running command is refused without
// asking anybody: the question would name nothing, and an escalation that names
// nothing is worth nothing. This is what a `sudo` typed by hand as the
// executor's account looks like.
func TestAnUnknownTokenIsRefusedWithoutAsking(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	// Registered and then finished, which is the late request this covers.
	token := mustRegister(s, run())
	s.Release(token, Outcome{})

	if approved, _, _ := s.Ask(procsFor(token)); approved {
		t.Error("a released token was approved")
	}
	if approved, _, _ := s.Ask(procsFor("0123456789abcdef")); approved {
		t.Error("an invented token was approved")
	}
	if h.questions() != 0 {
		t.Errorf("%d questions were put for requests naming no command", h.questions())
	}
}

// One question per brokered command: ansible calls sudo once per become'd task,
// and a question asked twenty times is one nobody reads. The keying is by run,
// so a later sudo from the same command joins that command's question rather
// than putting one of its own.
func TestOneApprovalCoversTheRestOfTheCommand(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)

	token := mustRegister(s, run())
	for i := range 5 {
		if approved, _, reason := s.Ask(procsFor(token)); !approved {
			t.Fatalf("request %d: %s", i, reason)
		}
	}
	if h.questions() != 1 {
		t.Errorf("5 sudos from one command put %d questions, want 1", h.questions())
	}
}

// The escalation is scoped to the command, not to a stretch of time: the next
// brokered command is asked about on its own, however soon it starts. This is
// what a password could not do, one being carriable from the approved run to
// this one, and what nothing here can be, there being nothing to carry.
func TestAnotherCommandIsAskedAboutSeparately(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)

	first := mustRegister(s, run())
	if approved, _, _ := s.Ask(procsFor(first)); !approved {
		t.Fatal("the first command was refused")
	}
	// The first run ends before the next starts, which is what the serialization
	// requires: two brokered commands do not run at once while one holds root.
	s.Release(first, Outcome{})

	second := mustRegister(s, Run{Argv: []string{"rm", "-rf", "/"}, Cwd: "/srv"})
	if approved, _, _ := s.Ask(procsFor(second)); !approved {
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

// The serialization, one half: while a run holds an escalation and has
// not ended, no other brokered command may start. They share the executor's
// uid, so a second could read the approved run's token from /proc and spend it
// on the root it was never shown for. Held, and admitted again once the run
// ends.
func TestAnEscalationHoldsEveryOtherCommand(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, run())

	go s.Ask(procsFor(first))
	id := waitForQuestion(t, s)
	if err := s.Answer(id, true, "operator"); err != nil {
		t.Fatalf("the first run was the only one, so it should approve: %v", err)
	}
	if _, heldBy := s.Register(Run{Argv: []string{"curl", "evil"}, Cwd: "/tmp"}); heldBy == "" {
		t.Error("a new command was admitted while an escalation was live: it " +
			"could read the approved run's token and ride it")
	}
	s.Release(first, Outcome{})
	if _, heldBy := s.Register(Run{Argv: []string{"curl", "ok"}, Cwd: "/tmp"}); heldBy != "" {
		t.Error("a command was still held after the approved run ended")
	}
}

// The two halves must be decided against the same instant. Register admits a
// run while no escalation is live; Answer approves while no other run is
// registered. A gap between Answer's sole-occupancy check and its marking the
// run approved is a window a second run starts in and then rides the escalation,
// so many concurrent rounds assert the two never both happen.
func TestAnEscalationAndASecondRunNeverCoexist(t *testing.T) {
	for range 400 {
		s := New(baseConfig())
		s.Owner = ownerFromRegistry(s)
		first := mustRegister(s, run())
		go s.Ask(procsFor(first))
		id := waitForQuestion(t, s)

		var wg sync.WaitGroup
		var approveErr error
		var secondHeldBy string
		wg.Add(2)
		go func() { defer wg.Done(); approveErr = s.Answer(id, true, "operator") }()
		go func() {
			defer wg.Done()
			_, secondHeldBy = s.Register(Run{Argv: []string{"curl", "evil"}, Cwd: "/tmp"})
		}()
		wg.Wait()

		if approveErr == nil && secondHeldBy == "" {
			t.Fatalf("the first run was approved while a second was admitted: the " +
				"second shares the executor uid and can ride the escalation")
		}
		s.Stop()
	}
}

// The other half: a run is not approved while any other brokered command is
// registered, that one being able to ride the escalation. The yes is turned
// into a no rather than the question being held open, which would make the
// operator poll the one interval in which the host has to be quiet.
func TestAnEscalationIsRefusedUntilTheHostIsQuiet(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, run())

	granted := make(chan bool, 1)
	go func() {
		approved, _, _ := s.Ask(procsFor(first))
		granted <- approved
	}()
	id := waitForQuestion(t, s)
	// The other run arrives after the question, which pend refuses to file
	// alongside one and Register refuses to admit beside one, so this is the
	// backstop rather than the path a host takes: the check has to hold whatever
	// admitted the second run, being the one that stands between a live escalation
	// and a command that could ride it.
	other := "0f0f0f0f0f0f0f0f"
	s.mu.Lock()
	s.runs[other] = Run{Argv: []string{"go", "build"}, Cwd: "/src", LogID: "log-2"}
	s.mu.Unlock()
	err := s.Answer(id, true, "operator")
	if err == nil {
		t.Fatal("approved a run while another brokered command was running")
	}
	if !strings.Contains(err.Error(), "go build") {
		t.Errorf("the refusal does not name the command that blocked it: %v", err)
	}
	if !errors.Is(err, ErrNotQuiescent) {
		t.Errorf("err = %v, want it to say the host was not quiet rather than that "+
			"the question was unknown", err)
	}
	// Answered, no, and closed. Not held open for another try: that would make
	// the operator poll the one interval in which the host has to be quiet, and
	// leave a yes standing against a condition that can change under it.
	if approved := <-granted; approved {
		t.Fatal("the sudo was approved while another brokered command was running")
	}
	if len(s.Questions()) != 0 {
		t.Error("the refused-for-quiet escalation left its question open rather than " +
			"answering it no")
	}
	// And the next question, from a run started after the host drained, takes.
	// Both go: the refused run's sudo failed, so that command is over too.
	s.Release(other, Outcome{})
	s.Release(first, Outcome{})
	second := mustRegister(s, run())
	go s.Ask(procsFor(second))
	if err := s.Answer(waitForQuestion(t, s), true, "operator"); err != nil {
		t.Fatalf("still refused after the host went quiet: %v", err)
	}
}

// An escalation dies with the command it was given for.
func TestAnEscalationDoesNotOutliveItsCommand(t *testing.T) {
	s := started(t, baseConfig())
	watching(t, s, true)

	token := mustRegister(s, run())
	if approved, _, _ := s.Ask(procsFor(token)); !approved {
		t.Fatal("refused")
	}
	s.Release(token, Outcome{})
	if approved, _, _ := s.Ask(procsFor(token)); approved {
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
		if approved, _, _ := s.Ask(procsFor(token)); approved {
			t.Fatalf("request %d was approved", i)
		}
	}
	if h.questions() != 2 {
		t.Errorf("two requests after a refusal put %d questions, want one each: a "+
			"no must not stand in for an escalation", h.questions())
	}
}

// A question nobody answers is refused rather than held open.
func TestAnUnansweredQuestionExpires(t *testing.T) {
	cfg := baseConfig()
	cfg.TimeoutSec = 1
	s := started(t, cfg)

	approved, _, reason := s.Ask(procsFor(mustRegister(s, run())))
	if approved {
		t.Error("a question nobody answered approved an escalation")
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
		wg.Go(func() {
			if approved, _, reason := s.Ask(procsFor(token)); !approved {
				refused <- reason
			}
		})
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
// answered: the audit log is where an operator asks what was approved, what was
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

	if approved, _, _ := s.Ask(procsFor(mustRegister(s, run()))); approved {
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
	if record["op"] != "escalate" {
		t.Errorf("op = %v, want escalate", record["op"])
	}
	if record["run_log_id"] != "log-1" {
		t.Errorf("run_log_id = %v, want the command's own record", record["run_log_id"])
	}
	if outcome, _ := record["outcome"].(string); !strings.Contains(outcome, "the test") {
		t.Errorf("outcome = %q, want it to name who answered", outcome)
	}
}

// -- what a request has to prove ---------------------------------------------

// A request from a process the executor did not fork is refused, and refused
// without asking anybody, even while a run is registered and somebody is
// watching for questions. This is the whole of what identifies a run: there is
// nothing a caller holds, so there is nothing for one to present.
func TestAProcessTheExecutorDidNotForkIsRefused(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	mustRegister(s, run())

	stranger := []int{999999}
	approved, code, _ := s.Ask(stranger)
	if approved {
		t.Error("a process no run forked was allowed to escalate")
	}
	if code != CodeUnownedRun {
		t.Errorf("code = %q, want %q", code, CodeUnownedRun)
	}
	if asked := h.questions(); asked != 0 {
		t.Errorf("%d question(s) were put about a process no run forked", asked)
	}
}

// A run this server does not hold is refused however the ancestry is shaped:
// whether a pid still names the process it was forked as is the executor's
// question, asked in that package by TestOwnerOfRefusesAReapedProcess.
func TestAnAncestryTheExecutorDoesNotOwnIsRefused(t *testing.T) {
	s := started(t, baseConfig())
	mustRegister(s, run())

	if approved, code, _ := s.Ask([]int{424242}); approved || code != CodeUnownedRun {
		t.Errorf("approved = %v, code = %q; a process no run forked was attributed "+
			"to a live run", approved, code)
	}
}

// Stop releases everything waiting rather than leaving sudo to sit until its
// own timeout after the broker has gone.
func TestStopReleasesWhatIsWaiting(t *testing.T) {
	s := New(baseConfig())
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, _, reason := s.Ask(procsFor(token))
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

// A command that ends takes its unanswered question with it. A question left
// filed would be shown by `faramir sudo approve` and would take a yes for a command
// that is no longer running, and it would hold the one question slot until its
// own timeout.
func TestReleasingACommandDropsItsUnansweredQuestion(t *testing.T) {
	s := started(t, baseConfig()) // TimeoutSec is 10: nothing here may wait that long
	token := mustRegister(s, run())

	done := make(chan string, 1)
	go func() {
		approved, _, reason := s.Ask(procsFor(token))
		if approved {
			done <- "approved"
			return
		}
		done <- reason
	}()
	id := waitForQuestion(t, s)

	s.Release(token, Outcome{})

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

// No question is put while another command is registered, and none is queued: a
// queue could only hold questions that cannot be answered yes, Answer refusing
// to approve while any other run is registered. The same argument keeps the
// first of them from being put.
func TestNoQuestionIsPutWhileAnotherCommandIsRegistered(t *testing.T) {
	s := started(t, baseConfig())
	h := watching(t, s, true)
	// Both tokens before either asks. A pending question holds a *new*
	// registration, so the only way two commands ask at once is both registering
	// while the host was quiet, which is what a burst of brokered commands looks
	// like, and the case this refuses.
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})

	approved, _, reason := s.Ask(procsFor(first))
	if approved {
		t.Fatal("a sudo was approved while a second command shared the executor's uid")
	}
	if !strings.Contains(reason, "playbook two") {
		t.Errorf("reason = %q, want the command in the way named", reason)
	}
	if _, raised, _, _ := s.pend(second, Run{Argv: []string{"playbook", "two"}}); raised {
		t.Fatal("the second command raised a question of its own")
	}
	if len(s.Questions()) != 0 {
		t.Errorf("%d question(s) waiting, want none: neither could be granted",
			len(s.Questions()))
	}
	if h.questions() != 0 {
		t.Errorf("a human was put to %d question(s) that could only be refused",
			h.questions())
	}
}

// The refusals pend can give are told apart. A host already holding a question
// and a stopping broker send an operator looking in different places, and one
// reported as the other sends them hunting for a pending question that is not
// there.
func TestARefusalSaysWhichLimitItHit(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})
	// Two commands registered, so neither may be approved whatever a human types:
	// each could read the other's token. The refusal names the one in the way.
	if _, _, _, reason := s.pend(first, run()); !strings.Contains(reason, "playbook two") {
		t.Errorf("reason = %q, want the other running command named", reason)
	}
	if _, _, _, reason := s.pend(second, run()); !strings.Contains(reason, "playbook one") {
		t.Errorf("reason = %q, want the other running command named", reason)
	}

	// A stopping broker, which Ask reaches when Stop lands between its own lookup
	// and this call.
	stopping := New(baseConfig())
	token := mustRegister(stopping, run())
	stopping.Stop()
	_, _, code, reason := stopping.pend(token, run())
	if !strings.Contains(reason, "stopping") {
		t.Errorf("reason = %q, want the stopping broker named rather than a busy host", reason)
	}
	if code != CodeBrokerStopped {
		t.Errorf("code = %q, want %q: a caller telling this from a refusal reads the "+
			"code, not the sentence", code, CodeBrokerStopped)
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
func TestPollBlocksUntilSomethingIsAsked(t *testing.T) {
	s := started(t, baseConfig())

	if got, _ := s.Poll(50*time.Millisecond, ""); len(got) != 0 {
		t.Errorf("Poll = %v with nothing waiting", got)
	}
	token := mustRegister(s, run())
	go func() { _, _, _ = s.Ask(procsFor(token)) }()

	questions, _ := s.Poll(5*time.Second, "")
	if len(questions) != 1 {
		t.Fatalf("Poll returned %d questions, want the one just asked", len(questions))
	}
	question := questions[0]
	if question.ID == "" || question.Prompt == "" {
		t.Errorf("a question with nothing to show: %+v", question)
	}
	if question.Cmd != "ansible-playbook msmtp.yml" {
		t.Errorf("cmd = %q, want the command being asked about", question.Cmd)
	}
}

// And the refusal is this one rather than a wait: the sudo comes back rather
// than blocking for [sudo] timeout_sec on a question nobody can grant.
func TestTheEarlyRefusalDoesNotBlock(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	_ = mustRegister(s, Run{Argv: []string{"playbook", "two"}})

	done := make(chan struct{})
	go func() { _, _, _ = s.Ask(procsFor(first)); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("the sudo blocked instead of being refused, so it is waiting out a " +
			"question that was never grantable")
	}
}

// Once the other command ends, the same run may ask: the refusal is about the
// host's state, not about this command.
func TestTheQuestionIsPutOnceTheOtherCommandEnds(t *testing.T) {
	s := started(t, baseConfig())
	first := mustRegister(s, Run{Argv: []string{"playbook", "one"}})
	second := mustRegister(s, Run{Argv: []string{"playbook", "two"}})
	if _, _, _, reason := s.pend(first, run()); reason == "" {
		t.Fatal("a question was filed with two commands registered")
	}
	s.Release(second, Outcome{})
	go func() { _, _, _ = s.Ask(procsFor(first)) }()
	waitForQuestion(t, s) // fails if none was put after the other command ended
}

// --------------------------------------------------------------------------
// What became of the run (`faramir sudo watch` reports the ending)
// --------------------------------------------------------------------------

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
	s.Release(token, Outcome{LogID: "log-1", ExitCode: &code, DurationSec: 1.5})

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

// --------------------------------------------------------------------------
// Which no it was
// --------------------------------------------------------------------------

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
