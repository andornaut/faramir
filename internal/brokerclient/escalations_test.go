package brokerclient

import (
	"os"
	"testing"

	"github.com/andornaut/faramir/internal/socktest"
)

// An unreachable broker is a refusal, not a pass. This is the shape of every
// failure below the guards: the daemon being down, the socket being gone, the
// question expiring. A helper that failed open here would make stopping the
// broker the way to sudo.
//
// Asked of Escalate rather than through the pam helper, so the subject
// is the answer to an unreachable broker rather than the walk above it.
func TestAnUnreachableBrokerRefuses(t *testing.T) {
	approved, _, err := Escalate("/nonexistent/faramir-escalate-test.sock", []int{os.Getpid()})
	if err == nil {
		t.Fatal("a broker that is not there answered")
	}
	if approved {
		t.Error("an unreachable broker authenticated a sudo")
	}
}

// A broker that could not be reached exits 69, and one that answered with a
// refusal exits 1: a script retrying on 69 would otherwise retry a refusal that
// will never change.
func TestARefusalIsNotAnUnreachableBroker(t *testing.T) {
	_, _, err := Escalations("/nonexistent/faramir-escalations-test.sock", 0, "", "")
	if got := FailureCode(err); got != ExitUnavailable {
		t.Errorf("an unreachable broker exits %d, want %d (%v)", got, ExitUnavailable, err)
	}

	path := socktest.AnsweringBroker(t, map[string]any{"error": map[string]any{"message": "forbidden"}})
	_, _, err = Escalations(path, 0, "", "")
	if err == nil {
		t.Fatal("a refusal came back as success")
	}
	if got := FailureCode(err); got != 1 {
		t.Errorf("a refusal exits %d, want 1 (%v)", got, err)
	}
}
