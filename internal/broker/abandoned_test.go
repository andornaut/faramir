package broker

import (
	"net"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// A run whose caller has gone is told so, and the executor kills the child on
// it. Without this the command runs to its timeout with nothing waiting for its
// output, holding one of the broker's concurrency slots: a handful of
// interrupted callers would hold all of them for as long as an hour.
//
// The caller here closes the connection rather than half-closing it, which is
// why `faramir run` keeps its write side open until it has an answer: a
// half-close would reach the broker as the caller having gone, and every
// brokered command would be killed the moment it started.
func TestARunLosesItsChildWhenTheCallerGoes(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	started, ended := make(chan struct{}), make(chan struct{})
	var sawAbandon bool
	s.exec = func(_ *redact.Redactor, _ func(string), req execclient.Request) (*execclient.Result, error) {
		close(started)
		// What the read loop does, at the speed a test can wait: ask until the
		// caller is gone or the deadline says it never will be.
		deadline := time.After(15 * time.Second)
		for {
			select {
			case <-req.Abandoned:
				sawAbandon = true
				close(ended)
				return &execclient.Result{ExitCode: 128 + 9, Abandoned: true}, nil
			case <-deadline:
				close(ended)
				return &execclient.Result{ExitCode: 0}, nil
			case <-time.After(10 * time.Millisecond):
			}
		}
	}

	dial := serving(t, s)
	conn, _ := dial()
	if err := sockutil.Send(conn, map[string]any{
		"version": version.Version, "op": "run",
		"cmd": []string{"true"}, "cwd": t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-started:
	case <-time.After(15 * time.Second):
		t.Fatal("the run never started")
	}

	// The caller goes without reading the answer, which is what a killed agent
	// and a Ctrl-C both look like from here.
	_ = conn.Close()

	select {
	case <-ended:
	case <-time.After(20 * time.Second):
		t.Fatal("the run never ended")
	}
	if !sawAbandon {
		t.Error("the run was never told its caller had gone, so it would have " +
			"run to its timeout")
	}
}

// And a caller that is still there does not read as one that has gone: the
// channel stays open for the whole of a run nobody interrupted. A watcher that
// fired on its own would kill every brokered command at once.
func TestARunWithACallerStillThereIsNotAbandoned(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	var abandonedEarly bool
	s.exec = func(_ *redact.Redactor, _ func(string), req execclient.Request) (*execclient.Result, error) {
		select {
		case <-req.Abandoned:
			abandonedEarly = true
		case <-time.After(300 * time.Millisecond):
		}
		return &execclient.Result{ExitCode: 0, Output: "done\n"}, nil
	}

	dial := serving(t, s)
	conn, lines := dial()
	if err := sockutil.Send(conn, map[string]any{
		"version": version.Version, "op": "run",
		"cmd": []string{"true"}, "cwd": t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	line, err := lines.Next()
	if err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if len(line) == 0 {
		t.Fatal("the connection closed without an answer")
	}
	if abandonedEarly {
		t.Error("a caller that was still waiting read as one that had gone")
	}
}

// An op that answers in a round trip is not watched at all: there is no window
// to be in, and watching would cost a goroutine per request.
func TestOnlyARunIsWatched(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	conn, _ := serving(t, s)()
	for _, op := range []string{"status", "refs", "redact", "refresh"} {
		t.Run(op, func(t *testing.T) {
			if s.watchPeer(conn, op) != nil {
				t.Errorf("%s is watched", op)
			}
		})
	}
	if s.watchPeer(conn, "run") == nil {
		t.Error("a run is not watched")
	}
}

// Bytes arriving on the connection are a caller that is still here, whatever
// it sent. Reading one and calling it an EOF would answer a caller that spoke
// out of turn by taking its command away, which is the opposite of what the
// watch is for.
func TestABusyCallerIsNotMistakenForOneThatHasGone(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	var abandonedEarly bool
	running := make(chan struct{})
	s.exec = func(_ *redact.Redactor, _ func(string), req execclient.Request) (*execclient.Result, error) {
		close(running)
		select {
		case <-req.Abandoned:
			abandonedEarly = true
		case <-time.After(500 * time.Millisecond):
		}
		return &execclient.Result{ExitCode: 0, Output: "done\n"}, nil
	}

	dial := serving(t, s)
	conn, lines := dial()
	if err := sockutil.Send(conn, map[string]any{
		"version": version.Version, "op": "run",
		"cmd": []string{"true"}, "cwd": t.TempDir(),
	}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-running:
	case <-time.After(15 * time.Second):
		t.Fatal("the run never started")
	}
	// More down the same connection while the run is in flight. Nothing faramir
	// ships does this; what matters is that it is not read as a caller leaving.
	if _, err := conn.Write([]byte("{\"op\":\"status\"}\n")); err != nil {
		t.Fatal(err)
	}

	if _, err := lines.Next(); err != nil {
		t.Fatalf("no answer: %v", err)
	}
	if abandonedEarly {
		t.Error("a caller that sent something read as one that had gone, so its " +
			"command was killed")
	}
}

// Close sweeps its connections by setting a deadline in the past, so a read
// parked on one returns a timeout. That is the broker stopping, not the caller
// leaving. The run ends either way, the executor tearing down a run whose
// broker has gone; what this decides is the reason, and a stop is not a caller
// walking away from its command.
//
// The watch ends there rather than resuming. A swept connection is not
// un-swept, and nothing else sets a deadline on one carrying a run.
func TestABrokerStoppingIsNotACallerLeaving(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	left, right := net.Pipe()
	defer func() { _ = left.Close(); _ = right.Close() }()

	gone := s.watchPeer(left, protocol.OpRun)
	if gone == nil {
		t.Fatal("a run is not watched")
	}
	// What Close does to a live connection.
	if err := left.SetDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gone:
		t.Fatal("a swept connection read as a caller that had gone, so a broker " +
			"stop would kill the command it is waiting for")
	case <-time.After(500 * time.Millisecond):
	}
}

// And a connection that simply closes is the caller leaving, which is the
// other half of the same question.
func TestAClosedConnectionIsACallerLeaving(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": goodValue})
	left, right := net.Pipe()
	defer func() { _ = left.Close() }()

	gone := s.watchPeer(left, protocol.OpRun)
	if gone == nil {
		t.Fatal("a run is not watched")
	}
	_ = right.Close()
	select {
	case <-gone:
	case <-time.After(15 * time.Second):
		t.Fatal("the caller left and the run was not told")
	}
}
