package escalation

import (
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
