package brokerclient

import (
	"os"
	"testing"
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
