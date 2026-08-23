package escalation

import (
	"testing"
	"time"
)

// A watcher's long poll is parked on a channel, not on its socket, so nothing
// the broker does to the connection ends it. Stop has to, or the daemon waits
// out the poll on every shutdown and systemd kills it at TimeoutStopSec.
func TestStopWakesAWatcherWithNothingWaiting(t *testing.T) {
	s := New(baseConfig())
	done := make(chan time.Duration, 1)
	go func() {
		start := time.Now()
		s.Poll(time.Minute, "")
		done <- time.Since(start)
	}()
	// Let the poll reach the wait rather than racing Stop to the lock.
	time.Sleep(50 * time.Millisecond)
	s.Stop()
	select {
	case took := <-done:
		if took > 5*time.Second {
			t.Fatalf("the poll took %v to return, so Stop did not release it", took)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the poll never returned, so a shutdown would wait it out")
	}
}

// And one arriving after the stop does not park at all.
func TestAPollAfterStopReturnsAtOnce(t *testing.T) {
	s := New(baseConfig())
	s.Stop()
	start := time.Now()
	s.Poll(time.Minute, "")
	if took := time.Since(start); took > 5*time.Second {
		t.Fatalf("the poll took %v, so a late watcher holds the shutdown open", took)
	}
}
