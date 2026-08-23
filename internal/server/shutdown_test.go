package server

import (
	"net"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// Serve waits on every connection goroutine before it returns, and a stream
// idling between chunks sits in a read [command] max_timeout_sec away. Nothing
// else ends that wait, so a stop took as long as the slowest peer: systemd gives
// TimeoutStopSec and then kills the broker instead of it exiting.
func TestClosingDoesNotWaitOutAStreamIdlingBetweenChunks(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	lines := sockutil.NewLineReader(conn, 1<<20)

	// One chunk saying another follows, and then nothing: the broker is now
	// parked in a read for as long as a brokered command may take.
	if err := sockutil.Send(conn, map[string]any{
		"op": "redact", "text": "x", "more": true,
		"version": version.Version}); err != nil {
		t.Fatal(err)
	}
	if _, err := lines.Next(); err != nil {
		t.Fatalf("the first chunk was not answered: %v", err)
	}

	start := time.Now()
	_ = s.Close()
	select {
	case <-served:
		if waited := time.Since(start); waited > 5*time.Second {
			t.Errorf("Serve took %v to return", waited)
		}
	case <-time.After(15 * time.Second):
		t.Fatalf("Serve did not return within 15s of Close, with [command] "+
			"max_timeout_sec at %ds: an idle stream is holding shutdown, which "+
			"systemd ends by killing the broker", s.Config.Command.MaxTimeoutSec)
	}
}

// The same for a connection that has sent nothing at all, where what ends the
// read is peerWait rather than the inter-chunk deadline.
func TestClosingDoesNotWaitOutASilentPeer(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan error, 1)
	go func() { served <- s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	// Give the broker a moment to be in its read before Close.
	time.Sleep(50 * time.Millisecond)

	_ = s.Close()
	select {
	case <-served:
	case <-time.After(15 * time.Second):
		t.Fatal("Serve did not return within 15s of Close for a peer that said nothing")
	}
}

// A connection accepted as Close ran is dropped rather than served: nothing is
// going to interrupt a goroutine that started after the sweep.
func TestAConnectionArrivingDuringCloseIsNotServed(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	left, right := net.Pipe()
	defer func() { _ = left.Close(); _ = right.Close() }()

	if !s.track(left) {
		t.Fatal("a connection was refused before Close")
	}
	s.untrack(left)
	_ = s.Close()
	if s.track(right) {
		t.Error("a connection was accepted for serving after Close, so nothing " +
			"would unblock it")
	}
}

// A chunk the broker refuses ends the connection. Continuing would hold a
// goroutine on the long inter-chunk deadline for a stream that has already been
// told it is not going to be redacted.
func TestARefusedChunkEndsTheConnection(t *testing.T) {
	// A managed file that was found and did not load: the broker knows values
	// are missing and cannot say which, so it refuses.
	s := newUnreadableServer(t)
	dial := serving(t, s)
	conn, lines := dial()

	if err := sockutil.Send(conn, map[string]any{
		"op": "redact", "text": "x", "more": true,
		"version": version.Version}); err != nil {
		t.Fatal(err)
	}
	line, err := lines.Next()
	if err != nil {
		t.Fatal(err)
	}
	if line == nil {
		t.Fatal("the refused chunk was not answered at all")
	}

	// Bounded, or a connection left open would park this read on the broker's
	// inter-chunk deadline instead of failing the test.
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	next, err := lines.Next()
	if err != nil {
		t.Fatalf("the connection was still open after a refusal: %v", err)
	}
	if next != nil {
		t.Errorf("a second response arrived: %s", next)
	}
}
