package main

// How a run's ending reaches the terminal that approved it.  A yes is the last
// decision the operator makes about that command, so this line is the only
// report they get of what it did, and each of its four shapes has to say
// something different.

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/approval"
)

func TestPrintOutcomeSaysHowTheRunEnded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome approval.Outcome
		want    []string
		absent  []string
	}{
		{
			name:    "a clean exit",
			outcome: approval.Outcome{LogID: "log-1", ExitCode: new(0), DurationSec: 12.44},
			want:    []string{"log-1 exited 0 after 12.4s"},
			absent:  []string{"timed out", "failed"},
		},
		{
			name:    "a non-zero exit",
			outcome: approval.Outcome{LogID: "log-2", ExitCode: new(2), DurationSec: 3.1},
			want:    []string{"log-2 exited 2 after 3.1s"},
		},
		{
			name: "a run the timeout ended",
			outcome: approval.Outcome{
				LogID: "log-3", ExitCode: new(124), DurationSec: 60, TimedOut: true,
			},
			want: []string{"log-3 exited 124", "timed out"},
		},
		{
			// The one that must not read as a clean exit: the broker got no status,
			// and a zero printed here would say the run succeeded.
			name:    "a run with no status",
			outcome: approval.Outcome{LogID: "log-4", Error: "the executor could not be reached"},
			want:    []string{"log-4 failed", "the executor could not be reached"},
			absent:  []string{"exited 0", "exited"},
		},
		{
			name:    "a run released without either",
			outcome: approval.Outcome{LogID: "log-5"},
			want:    []string{"log-5 ended", "no exit status"},
			absent:  []string{"exited 0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := captureStdout(t, func() int { printOutcome(tc.outcome); return 0 })
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("the ending does not say %q: %q", want, out)
				}
			}
			for _, absent := range tc.absent {
				if strings.Contains(out, absent) {
					t.Errorf("the ending says %q, which is not what happened: %q", absent, out)
				}
			}
		})
	}
}
