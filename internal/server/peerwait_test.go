package server

import (
	"bytes"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/executor"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/version"
)

// A peer that asks and then never reads its reply must not hold this broker.
//
// The reply to an exec carries the command's output, which can be larger than a
// socket buffer, so the write blocks until somebody reads it. With no deadline
// on that write the goroutine, the descriptor and the whole response are held
// for as long as the peer cares to hold them, by the account the coding agent
// runs as; and Serve waits on those goroutines, so the broker stops answering
// `systemctl stop` too.
func TestAPeerThatNeverReadsDoesNotHoldTheBroker(t *testing.T) {
	original := peerWait
	peerWait = 200 * time.Millisecond
	t.Cleanup(func() { peerWait = original })

	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	// Larger than any socket buffer, so the reply cannot be handed to the kernel
	// and forgotten: the write is still in progress when the peer walks away.
	huge := strings.Repeat("x", 8<<20)
	s.exec = func(_ *redact.Redactor, sink func(string), _ executor.Request) (*executor.Result, error) {
		sink(huge)
		return &executor.Result{Output: huge}, nil
	}
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	served := make(chan struct{})
	go func() {
		_ = s.Serve()
		close(served)
	}()

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(
		`{"op":"run","version":"` + version.Version + `","cmd":["true"],"cwd":"/"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	// And no read at all while the deadline runs out. The connection stays open,
	// which is the case a peer that hung up would not exercise: a closed socket
	// ends the write by itself.
	time.Sleep(5 * peerWait)

	// Only now, and the reply has to come up short: what the socket buffer took
	// before the write blocked, and then the end of a connection the broker gave
	// up on. Without the deadline the broker is still holding the write, and
	// draining here would collect the whole 8MB and a well-formed reply.
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	read := 0
	buf := make([]byte, 65536)
	for {
		n, err := conn.Read(buf)
		read += n
		if err != nil {
			break
		}
		if read >= len(huge) {
			t.Fatalf("the broker wrote the whole %d-byte reply to a peer that spent "+
				"%v not reading it", read, 5*peerWait)
		}
	}

	// And the goroutine went with it: Serve waits for every connection, so one
	// stuck in a write is a broker that never stops.
	_ = s.Close()
	select {
	case <-served:
	case <-time.After(15 * time.Second):
		t.Fatal("the broker did not shut down: a reply nobody read is still being " +
			"written, and Serve waits for that goroutine")
	}
}

// The deadline is the reply's own, not one carried over from reading the
// request: an op takes as long as the command it runs, and a request line is
// read on a clock that has nothing to do with it.
func TestALongOpDoesNotRunOutTheRequestDeadline(t *testing.T) {
	original := peerWait
	peerWait = 300 * time.Millisecond
	t.Cleanup(func() { peerWait = original })

	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	s.exec = func(_ *redact.Redactor, _ func(string), _ executor.Request) (*executor.Result, error) {
		// Longer than peerWait, which is what a real command routinely is.
		time.Sleep(600 * time.Millisecond)
		return &executor.Result{Output: "done", ExitCode: 0}, nil
	}
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if _, err := conn.Write([]byte(
		`{"op":"run","version":"` + version.Version + `","cmd":["true"],"cwd":"/"}` + "\n")); err != nil {
		t.Fatal(err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	line, err := readReply(conn)
	if err != nil {
		t.Fatalf("a command that outlived the request deadline lost its reply: %v", err)
	}
	if !strings.Contains(line, `"done"`) {
		t.Errorf("reply does not carry the command's output: %s", line)
	}
}

// readReply is one response line.
func readReply(conn net.Conn) (string, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 65536)
	for {
		n, err := conn.Read(chunk)
		buf = append(buf, chunk[:n]...)
		if line, _, found := bytes.Cut(buf, []byte{'\n'}); found {
			return string(line), nil
		}
		if err != nil {
			return "", err
		}
	}
}
