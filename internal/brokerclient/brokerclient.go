// Package brokerclient talks to the broker over its unix socket: one request,
// one response, and the streaming form redaction needs.
//
// Two things about the socket decide the shape of everything here.
//
// The write half stays open for the whole of a request, though nothing more is
// sent down it. It is what tells the broker this caller is still here: a run is
// killed when its caller's connection goes, and a half-close would read as one,
// so a client that tidied up after writing would kill every command it started.
//
// A stream goes down one connection, each chunk but the last marked "more". The
// broker keeps one redactor for that connection, so the tail it holds back
// covers the join between chunks: a line longer than a chunk is broken
// mid-line, and a value that straddles the break belongs to neither half on its
// own.
//
// How long to wait is built from the request rather than fixed. A command's own
// timeout is what makes a wait long, and a ceiling of the client's own could
// fall below what the broker will honour, which would read as a broker that
// never answered.
package brokerclient

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net"
	"os/exec"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// chunkBytes is how much text one redact request carries. Well under the
// broker's max_request_bytes, which applies to the JSON-encoded line: a control
// byte becomes six characters, so this cannot exceed it however badly it
// encodes.
const chunkBytes = 32 << 10

// idleFlushInterval bounds how long buffered output waits when a live stream
// goes quiet below chunkBytes. Without it a backgrounded command that prints a
// line and then blocks holds that line unshown until it produces a whole chunk
// or exits, which for a server is never. Short enough to read as immediate,
// long enough that a burst still coalesces into one request.
const idleFlushInterval = 200 * time.Millisecond

// streamer carries the redaction of one stream: the pending bytes, the one
// connection they go down, and where the redacted result is written.
type streamer struct {
	stream *redactConn
	out    io.Writer
	buf    []byte
}

func (s *streamer) pending() bool { return len(s.buf) > 0 }

// flush sends the pending bytes. more false is the last chunk, which releases
// the tail the broker holds back.
func (s *streamer) flush(more bool) error {
	// An empty buffer is nothing to send, except as the last chunk of a stream
	// that has already sent something: that one is what releases the tail.
	if len(s.buf) == 0 && (more || !s.stream.open()) {
		return nil
	}
	text := string(s.buf)
	s.buf = s.buf[:0]
	redacted, err := s.stream.send(text, more)
	if err != nil {
		return fmt.Errorf("withheld %d byte(s) that could not be redacted, "+
			"and stopped there: %w", len(text), err)
	}
	_, writeErr := io.WriteString(s.out, redacted)
	return writeErr
}

// feed folds one ReadSlice result into the stream, sending a chunk when one is
// full. done is true once the stream is complete or has failed; retErr is what
// redactStream should then return. line is copied into buf, so it need only be
// valid for the call.
func (s *streamer) feed(line []byte, err error) (done bool, retErr error) {
	// Flushed before the append: a partial buffer plus a full ReadSlice would make
	// one request of nearly twice chunkBytes, which the broker could refuse.
	if len(s.buf) > 0 && len(s.buf)+len(line) > chunkBytes {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
	}
	s.buf = append(s.buf, line...)
	// A long line arrives in pieces; send what is there.
	if errors.Is(err, bufio.ErrBufferFull) {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
		return false, nil
	}
	if len(s.buf) >= chunkBytes {
		if flushErr := s.flush(true); flushErr != nil {
			return true, flushErr
		}
	}
	if err != nil {
		if flushErr := s.flush(false); flushErr != nil {
			return true, flushErr
		}
		if errors.Is(err, io.EOF) {
			return true, nil
		}
		return true, err
	}
	return false, nil
}

// ChildExitCode is the status faramir should exit with for a child that has
// finished. Nil is a clean exit. An exit status is kept as it is. A signal
// death has no exit status -- ExitError.ExitCode answers -1, which os.Exit
// renders as 255 -- so it is mapped to 128+signal, which is what a shell
// reports and what `faramir run` returns for the same death. A -1 return means
// the error was not a child exit at all, for the caller to report and treat as
// its own failure.
func ChildExitCode(err error) int {
	if err == nil {
		return 0
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) {
		return -1
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return 128 + int(status.Signal())
	}
	return exitErr.ExitCode()
}

// RedactStream sends the input through the broker a chunk at a time, breaking
// on a newline where it can. ReadSlice rather than ReadBytes, which would grow
// one long line past max_request_bytes.
//
// Every chunk goes down one connection, each but the last marked "more". The
// broker keeps one redactor for that connection, so the tail it holds back
// covers the join: a line longer than a chunk is broken mid-line, and a value
// across that break belongs to neither half on its own.
//
// A chunk that cannot be redacted is never written, and neither is anything
// after it. Chunks already written were redacted successfully, so they stay:
// buffering to be able to withhold them would mean an unbounded buffer and no
// incremental output. A failure shows as output that stops early.
func RedactStream(socketPath string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, chunkBytes)
	s := &streamer{stream: &redactConn{socketPath: socketPath}, out: out}
	defer s.stream.close()

	for {
		line, err := reader.ReadSlice('\n')
		if done, retErr := s.feed(line, err); done {
			return retErr
		}
	}
}

// RedactStreamLive is redactStream for a stream that must show output as it
// arrives rather than only when a chunk fills: the redacted stdout of a
// backgrounded command, which the guard pipes here.
//
// A reader goroutine, because ReadSlice blocks and a pipe inherited as stdin
// does not take a read deadline. It copies each read before sending, the
// ReadSlice slice being valid only until the next read; the main loop owns buf
// and the connection. On an early return the deferred close(done) frees a
// goroutine parked on the send, and one still parked in ReadSlice ends with the
// process.
func RedactStreamLive(socketPath string, in io.Reader, out io.Writer) error {
	reader := bufio.NewReaderSize(in, chunkBytes)
	s := &streamer{stream: &redactConn{socketPath: socketPath}, out: out}
	defer s.stream.close()

	type item struct {
		data []byte
		err  error
	}
	ch := make(chan item, 1)
	done := make(chan struct{})
	defer close(done)
	go func() {
		for {
			line, err := reader.ReadSlice('\n')
			cp := append([]byte(nil), line...)
			select {
			case ch <- item{cp, err}:
			case <-done:
				return
			}
			// ErrBufferFull is not the end: a line longer than the buffer has more to
			// come. Any other error, EOF included, ends the read.
			if err != nil && !errors.Is(err, bufio.ErrBufferFull) {
				return
			}
		}
	}()

	for {
		// Armed only when something is waiting, so a silent stream makes no
		// requests.
		var idle <-chan time.Time
		if s.pending() {
			idle = time.After(idleFlushInterval)
		}
		select {
		case it := <-ch:
			if finished, retErr := s.feed(it.data, it.err); finished {
				return retErr
			}
		case <-idle:
			if err := s.flush(true); err != nil {
				return err
			}
		}
	}
}

// redactConn is the one connection a stream's chunks go down. Dialed on the
// first chunk, so an input that turns out to be empty costs no connection and
// writes no audit record.
type redactConn struct {
	socketPath string
	conn       net.Conn
	lines      *sockutil.LineReader
}

func (rc *redactConn) open() bool { return rc.conn != nil }

func (rc *redactConn) close() {
	if rc.conn != nil {
		_ = rc.conn.Close()
		rc.conn = nil
	}
}

// send writes one chunk and reads its answer, strictly alternating rather than
// pipelined.
func (rc *redactConn) send(text string, more bool) (string, error) {
	if rc.conn == nil {
		conn, err := (&net.Dialer{Timeout: DialWait}).DialContext(
			context.Background(), "unix", rc.socketPath)
		if err != nil {
			return "", err
		}
		rc.conn, rc.lines = conn, sockutil.NewLineReader(conn, 1<<26)
	}
	// Per chunk, and refreshed for each: a redact runs no command, so an answer
	// that has not arrived by now is not coming. The deadline covers the write as
	// well.
	_ = rc.conn.SetDeadline(time.Now().Add(quickWait))
	request := map[string]any{"op": "redact", "text": text, "version": version.Version}
	if more {
		request["more"] = true
	}
	if err := sockutil.Send(rc.conn, request); err != nil {
		return "", err
	}
	line, err := rc.lines.Next()
	if err != nil {
		// Named, not flattened: an oversized request and a reset connection want
		// different fixes.
		return "", fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return "", errors.New("broker closed the connection without responding")
	}
	var response struct {
		Output string `json:"output"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return "", fmt.Errorf("malformed response: %w", err)
	}
	if response.Error != nil {
		return "", fmt.Errorf("%s", response.Error.Message)
	}
	return response.Output, nil
}

// Bounds on how long this side waits for the broker. The socket is systemd's
// and stays listening whether or not the service behind it can start, so a
// broker that never becomes ready accepts the connection and answers nothing.
const (
	// DialWait is reaching the socket, which is local and immediate or broken.
	DialWait = 5 * time.Second
	// quickWait bounds a round trip that runs no command.
	quickWait = 15 * time.Second
	// execGrace is what a brokered command's own timeout is padded by: the broker
	// kills at the timeout and still has to write the record and the response.
	execGrace = 30 * time.Second
)

// ResponseWait is how long to wait for this request's answer. A command's own
// timeout is what makes the wait long, so it is what the bound is built from.
//
// Saturating. A caller may name any positive integer and the broker clamps it to
// [command] max_timeout_sec, but multiplying an unclamped one into a Duration
// overflows int64 nanoseconds somewhere past 292 years, and a deadline built
// from a negative duration is one already past: the request then fails on the
// write with "i/o timeout" and no command runs, which reads as a broker that is
// not there rather than as a number nothing could wait that long for.
func ResponseWait(request map[string]any) time.Duration {
	if request["op"] != OpRun {
		return quickWait
	}
	// A named -t is the bound the broker will clamp to and honour, so the wait is
	// built from it. With no -t the broker applies its own default and enforces
	// [command] max_timeout_sec, which cannot be read from here and is only
	// lower-bounded by config: a fixed ceiling of the client's own could fall
	// below it and hang up on a within-policy run, which reads as a broker that
	// never answered and makes it kill the run. So the client sets no ceiling of
	// its own; it waits the largest span a Duration holds and lets the broker's
	// answer end the wait. Overflow is the only bound.
	seconds := maxWaitSeconds
	if s, ok := request["timeout_sec"].(int); ok && s > 0 && s < maxWaitSeconds {
		seconds = s
	}
	return time.Duration(seconds)*time.Second + execGrace
}

// maxWaitSeconds is the largest command timeout responseWait can add execGrace
// to and still hold in a Duration.
const maxWaitSeconds = int(math.MaxInt64/int64(time.Second)) - int(execGrace/time.Second)

// ExitFor is the status a refused request exits with. One code is separated
// out: a broker at its concurrency limit refused nothing about the command and
// the same request succeeds a moment later, so a caller driving faramir from a
// script can retry it rather than reading stderr to find out whether it should.
// Every other refusal is 1, the command not having run for a reason retrying
// does not change. An escalation already in flight is deliberately not here:
// docs/design.md has why that one is terminal.
func ExitFor(code string) int {
	switch code {
	case "busy":
		return 75 // EX_TEMPFAIL
	// The shell's two, so a script can branch on them the way it does on any
	// other command: 127 for a program that is not there, 126 for one that is
	// and cannot be run. `faramir redact -- command` runs its command itself
	// and has always given these; a brokered run gives them now.
	case "not_found":
		return 127
	case "not_executable":
		return 126
	}
	return 1
}

// RoundTrip is send() for a caller that reads the body itself, and with a
// deadline of its own: the escalations op holds the connection open on
// purpose.
func RoundTrip(socketPath string, request map[string]any, timeout time.Duration) ([]byte, error) {
	return roundTrip(socketPath, request, 5*time.Second, timeout)
}

// roundTrip is RoundTrip with the dial bounded separately from the read: a
// caller that can proceed without the broker gives up on the dial sooner.
func roundTrip(socketPath string, request map[string]any, dialWait, timeout time.Duration) ([]byte, error) {
	request["version"] = version.Version
	conn, err := (&net.Dialer{Timeout: dialWait}).DialContext(
		context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := sockutil.Send(conn, request); err != nil {
		return nil, err
	}
	// The write half stays open. The broker reads this connection for the whole
	// of a run and takes an EOF as the caller having gone, killing the command;
	// nothing on this socket half-closes, so there is no per-op rule to get
	// wrong when an op becomes a long one.
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("reading the response: %w", err)
	}
	if len(line) == 0 {
		return nil, errors.New("the broker closed the connection without answering")
	}
	return line, nil
}

// OpRun is the broker operation that runs a command, the one whose answer is
// worth waiting on for longer than a round trip. Not the `exec` subcommand,
// which is the executor daemon.
const OpRun = "run"
