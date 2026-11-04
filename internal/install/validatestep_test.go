package install

import (
	"errors"
	"testing"

	"github.com/andornaut/faramir/internal/runcmd"
)

// The probe's error is runcmd's, with `faramir run`'s stderr folded under the
// command line, so the extraction is pinned against that shape rather than a
// hand-written one.
func TestAnEscalationHeldElsewhereIsNamed(t *testing.T) {
	_, err := runcmd.Output("sh", "-c", `printf '%s\n%s\n' `+
		`'faramir run: escalation_in_progress: sudo make x is waiting to be approved. `+
		`Not run and not queued; run it again once that one has finished' `+
		`'faramir run: log_id=abc' >&2; exit 1`)
	if err == nil {
		t.Fatal("the probe did not fail, so this asserts nothing")
	}
	if got, want := escalationHeld(err), "sudo make x is waiting to be approved"; got != want {
		t.Errorf("got %q, want %q from:\n%v", got, want, err)
	}
	if got := escalationHeld(errors.New("faramir run: busy: at the limit")); got != "" {
		t.Errorf("another refusal read as a held escalation: %q", got)
	}
}
