package escalation

// The round trip.

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

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
