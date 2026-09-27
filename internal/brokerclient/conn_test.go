package brokerclient

import (
	"net"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/socktest"
)

// A broker that took the request and went away without answering did not
// answer, which is ExitUnavailable whichever client met it: the redaction
// stream as much as a round trip.
func TestABrokerThatClosesWithoutAnsweringIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			_ = conn.Close()
		}
	}()

	_, _, err = Escalations(path, 0, "", "")
	if got := FailureCode(err); got != ExitUnavailable {
		t.Errorf("a round trip exits %d, want %d (%v)", got, ExitUnavailable, err)
	}
	rc := &redactConn{socketPath: path}
	defer rc.close()
	if _, err := rc.send("text", false); FailureCode(err) != ExitUnavailable {
		t.Errorf("the redaction stream exits %d, want %d (%v)", FailureCode(err), ExitUnavailable, err)
	}
}

// A reply past the limit is an answer, and the same request gets the same one
// again, so it is not ExitUnavailable, which a caller retries on.
func TestAnOversizedReplyIsNotUnavailable(t *testing.T) {
	path := socktest.AnsweringBroker(t, map[string]any{"questions": strings.Repeat("x", 2<<20)})
	conn, err := Dial(path, time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_, err = conn.Exchange(map[string]any{"op": "escalations"}, 5*time.Second)
	if err == nil {
		t.Fatal("a reply past the limit was read")
	}
	if got := FailureCode(err); got != 1 {
		t.Errorf("an oversized reply exits %d, want 1 (%v)", got, err)
	}
}
