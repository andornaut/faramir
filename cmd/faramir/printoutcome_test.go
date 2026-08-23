package main

// How a run's ending reaches the terminal that approved it. A yes is the last
// decision the operator makes about that command, so this line is the only
// report they get of what it did, and each of its four shapes has to say
// something different.

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/escalation"
)

func TestPrintOutcomeSaysHowTheRunEnded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		outcome escalation.Outcome
		want    []string
		absent  []string
	}{
		{
			name:    "a clean exit",
			outcome: escalation.Outcome{LogID: "log-1", ExitCode: new(0), DurationSec: 12.44},
			want:    []string{"log-1 exited 0 in 12.4s"},
			absent:  []string{"timed out", "failed"},
		},
		{
			// The duration is wall time and the child sits inside sudo for the whole
			// escalation, so a run answered slowly would read as a slow command. The
			// run time leads and the total is kept: the timeout is enforced against
			// the total, so a kill at timeout_sec is unexplainable without it.
			name: "an escalation that took a while to answer",
			outcome: escalation.Outcome{
				LogID: "log-6", ExitCode: new(0), DurationSec: 41.03, WaitedSec: 40.01,
			},
			want: []string{"log-6 exited 0 in 1.0s",
				"40.0s waiting to be approved", "41.0s total"},
			absent: []string{"failed", "timed out"},
		},
		{
			// Under a second is not worth a clause: every approved run waits a little.
			name: "an escalation answered at once",
			outcome: escalation.Outcome{
				LogID: "log-7", ExitCode: new(0), DurationSec: 12.44, WaitedSec: 0.4,
			},
			want:   []string{"log-7 exited 0 in 12.4s"},
			absent: []string{"waiting", "total"},
		},
		{
			name:    "a non-zero exit",
			outcome: escalation.Outcome{LogID: "log-2", ExitCode: new(2), DurationSec: 3.1},
			want:    []string{"log-2 exited 2 in 3.1s"},
		},
		{
			name: "a run the timeout ended",
			outcome: escalation.Outcome{
				LogID: "log-3", ExitCode: new(124), DurationSec: 60, TimedOut: true,
			},
			want: []string{"log-3 exited 124", "timed out"},
		},
		{
			// The one that must not read as a clean exit: the broker got no status,
			// and a zero printed here would say the run succeeded.
			name:    "a run with no status",
			outcome: escalation.Outcome{LogID: "log-4", Error: "the executor could not be reached"},
			want:    []string{"log-4 failed", "the executor could not be reached"},
			absent:  []string{"exited 0", "exited"},
		},
		{
			name:    "a run released without either",
			outcome: escalation.Outcome{LogID: "log-5"},
			want:    []string{"log-5 ended", "no exit status"},
			absent:  []string{"exited 0"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out, _ := captureStdout(t, func() int { printOutcome(tc.outcome, palette{}); return 0 })
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

// The number the operator is reading for is how long the command took, and a
// run blocked on its own escalation makes that the one number the line did not
// carry: the reader had to subtract. This asserts the subtraction is done.
func TestTheOutcomeLeadsWithTheRunTimeRatherThanTheWallClock(t *testing.T) {
	// A script that failed the instant it was approved, after fifty seconds
	// waiting for a yes. It ran for no time at all, and "after 50.5s" said the
	// opposite.
	out, _ := captureStdout(t, func() int {
		printOutcome(escalation.Outcome{
			LogID: "log-8", ExitCode: new(1), DurationSec: 50.52, WaitedSec: 50.51,
		}, palette{})
		return 0
	})
	if !strings.Contains(out, "exited 1 in 0.0s") {
		t.Errorf("the run time does not lead: %q", out)
	}
	if !strings.Contains(out, "50.5s total") {
		t.Errorf("the total is gone, and the timeout is enforced against it: %q", out)
	}
}
