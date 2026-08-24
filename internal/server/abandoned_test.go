package server

import (
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/executor"
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
	s.exec = func(_ *redact.Redactor, _ func(string), req executor.Request) (*executor.Result, error) {
		close(started)
		// What the read loop does, at the speed a test can wait: ask until the
		// caller is gone or the deadline says it never will be.
		deadline := time.After(15 * time.Second)
		for {
			select {
			case <-req.Abandoned:
				sawAbandon = true
				close(ended)
				return &executor.Result{ExitCode: 128 + 9, Abandoned: true}, nil
			case <-deadline:
				close(ended)
				return &executor.Result{ExitCode: 0}, nil
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
	s.exec = func(_ *redact.Redactor, _ func(string), req executor.Request) (*executor.Result, error) {
		select {
		case <-req.Abandoned:
			abandonedEarly = true
		case <-time.After(300 * time.Millisecond):
		}
		return &executor.Result{ExitCode: 0, Output: "done\n"}, nil
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
			watched, stop := s.watchPeer(conn, op)
			defer stop()
			if watched != nil {
				t.Errorf("%s is watched", op)
			}
		})
	}
	watched, stop := s.watchPeer(conn, "run")
	defer stop()
	if watched == nil {
		t.Error("a run is not watched")
	}
}
