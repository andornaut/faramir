package protocol

import (
	"strings"
	"testing"
)

// init and three of doctor's checks shell back into the broker. Inside a
// brokered command every one of them is refused, the outer command holding the
// escalation, and the refusal names the lock rather than the nesting. This is
// what lets each caller say which it met.
func TestNestedRunIsDetectedFromTheOperatorMarker(t *testing.T) {
	t.Setenv(OperatorEnv, "op")
	why := NestedRun()
	if why == "" {
		t.Fatal("a brokered command was not detected, so a nested `faramir run` " +
			"would be reported as a broken install")
	}
	// The marker has to be in it: an operator reading the message has no other
	// way to tell which of the two situations they are in.
	if !strings.Contains(why, OperatorEnv) {
		t.Errorf("the reason does not name %s: %s", OperatorEnv, why)
	}
}

// An ordinary shell is left alone, which is every other way these run: saying
// "you are inside a brokered command" to somebody who is not would send them
// after a cause that is not there.
func TestNestedRunIsQuietOutsideOne(t *testing.T) {
	t.Setenv(OperatorEnv, "")
	if why := NestedRun(); why != "" {
		t.Errorf("an ordinary shell was read as a brokered command: %s", why)
	}
}
