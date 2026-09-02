package main

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/brokerclient"
)

// The sentence stands next to "wrote the file", so each of the three answers
// has to read as a different state of the value: covered, not known to be
// covered, and refused with the reason.
func TestTheNoteSaysWhetherTheValueIsCoveredYet(t *testing.T) {
	const waiting = "it picks this up within one refresh interval"
	for _, tc := range []struct {
		name, answer string
		says         []string
	}{
		{"the broker re-read it", brokerclient.RefreshOK, []string{"has re-read it"}},
		{"the broker did not answer", "", []string{"did not answer", waiting}},
		{"the broker refused", "unknown op refresh",
			[]string{"refused", "unknown op refresh", waiting}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := reReadNote(tc.answer, waiting)
			for _, want := range tc.says {
				if !strings.Contains(note, want) {
					t.Errorf("note = %q, want it to say %q", note, want)
				}
			}
		})
	}
}
