package brokerclient

import (
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
			map[string]any{"op": "run", "timeout_sec": 30}, 30*time.Second + ExecGrace},
		{"no timeout given, so the broker's own max decides and the client does not preempt it",
			map[string]any{"op": "run"}, time.Duration(MaxWaitSeconds)*time.Second + ExecGrace},
		{"a request that runs no command", map[string]any{"op": "status"}, QuickWait},
		{"nor does listing", map[string]any{"op": "refs"}, QuickWait},
		{"nor does a redact", map[string]any{"op": "redact", "text": "x"}, QuickWait},
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
