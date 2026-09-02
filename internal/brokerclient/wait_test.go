package brokerclient

import (
	"math"
	"testing"
	"time"
)

// The socket is systemd's and listens whether or not the daemon behind it
// started, so a broker that never becomes ready accepts the connection and
// answers nothing. A request that runs no command, and a run with its own -t,
// are bounded tightly. A run with no -t defers to the broker, which enforces
// [command] max_timeout_sec the client cannot read: the client sets no ceiling
// that could fall below it and kill a within-policy run, so its wait is the
// largest a Duration holds. Every wait stays finite, which is what keeps a
// multiplied timeout from overflowing into a deadline already past.
func TestTheWaitForAnAnswerIsBounded(t *testing.T) {
	for _, tc := range []struct {
		name    string
		request map[string]any
		want    time.Duration
	}{
		{"a command's own timeout, plus room to be killed and recorded",
			map[string]any{"op": "run", "timeout_sec": 30}, 30*time.Second + execGrace},
		{"no timeout given, so the broker's own max decides and the client does not preempt it",
			map[string]any{"op": "run"}, time.Duration(maxWaitSeconds)*time.Second + execGrace},
		{"a request that runs no command", map[string]any{"op": "status"}, quickWait},
		{"nor does listing", map[string]any{"op": "refs"}, quickWait},
		{"nor does a redact", map[string]any{"op": "redact", "text": "x"}, quickWait},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ResponseWait(tc.request); got != tc.want {
				t.Errorf("responseWait = %s, want %s", got, tc.want)
			}
		})
	}
	// Every bound is finite, which is the whole point.
	for _, op := range []string{"run", "status", "refs", "redact", "approve"} {
		if wait := ResponseWait(map[string]any{"op": op}); wait <= 0 {
			t.Errorf("%s waits %s, which is not a bound", op, wait)
		}
	}
}

// A command timeout is any positive integer the caller likes, clamped by the
// broker to [command] max_timeout_sec. The wait built from it is a Duration,
// and int64 nanoseconds run out somewhere past 292 years: an unsaturated
// multiplication wraps negative there, the deadline is already past, and the
// request fails on the write with "i/o timeout" before a command is run. That
// reads as a broker that is not there.
func TestTheResponseWaitDoesNotWrapOnAHugeTimeout(t *testing.T) {
	for _, seconds := range []int{
		1, 600, 3600, 1 << 30, maxWaitSeconds, maxWaitSeconds + 1,
		1 << 62, math.MaxInt64,
	} {
		got := ResponseWait(map[string]any{"op": OpRun, "timeout_sec": seconds})
		if got <= 0 {
			t.Errorf("responseWait(%d) = %v, which is a deadline already past", seconds, got)
		}
		if got < execGrace {
			t.Errorf("responseWait(%d) = %v, shorter than the grace alone", seconds, got)
		}
	}
	// And the ordinary values still get what they asked for plus the grace.
	if got, want := ResponseWait(map[string]any{"op": OpRun, "timeout_sec": 600}),
		600*time.Second+execGrace; got != want {
		t.Errorf("responseWait(600) = %v, want %v", got, want)
	}
}
