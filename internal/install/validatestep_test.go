package install

import (
	"errors"
	"testing"
)

func TestAnEscalationHeldElsewhereIsNamed(t *testing.T) {
	err := errors.New("faramir run -C / --quiet -- ssh-add -l: exit status 1: " +
		"faramir run: escalation_in_progress: sudo make x is waiting to be approved, and no other brokered command runs while one is\n" +
		"faramir run: log_id=abc")
	if got, want := escalationHeld(err), "sudo make x is waiting to be approved"; got != want {
		t.Errorf("got %q, want %q", got, want)
	}
	if got := escalationHeld(errors.New("faramir run: busy: at the limit")); got != "" {
		t.Errorf("another refusal read as a held escalation: %q", got)
	}
}
