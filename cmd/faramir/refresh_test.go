package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/sockutil"
)

// refreshBroker answers one op on a socket of its own and hands back the path.
// A nil reply closes the connection without answering, which is the broker
// restarting under the request rather than refusing it.
func refreshBroker(t *testing.T, reply map[string]any) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := sockutil.ReadLine(conn, 1<<20); err != nil {
					return
				}
				if reply == nil {
					return
				}
				_ = sockutil.Send(conn, reply)
			}()
		}
	}()
	return socketPath
}

// The op the broker is sent is what an older build refuses, so the request has
// to name it.
func TestTheBrokerIsAskedToRefresh(t *testing.T) {
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	asked := make(chan map[string]any, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer func() { _ = conn.Close() }()
		line, err := sockutil.ReadLine(conn, 1<<20)
		if err != nil {
			return
		}
		var request map[string]any
		_ = json.Unmarshal(line, &request)
		asked <- request
		_ = sockutil.Send(conn, map[string]any{"ok": true})
	}()

	t.Setenv("FARAMIR_SOCKET", socketPath)
	if answer := tellBrokerToReRead(); answer != reReadOK {
		t.Fatalf("tellBrokerToReRead = %q, want %q", answer, reReadOK)
	}
	request := <-asked
	if request["op"] != "refresh" {
		t.Errorf("op = %v, want refresh", request["op"])
	}
	if request["version"] == nil || request["version"] == "" {
		t.Error("the request carries no version, so a broker cannot report skew")
	}
}

// A broker that answered and said no. The message is what says which of the
// two silences an operator is looking at, so it has to come back rather than
// be flattened into the same empty answer as no broker at all.
func TestABrokerThatRefusesTheRefreshCarriesItsMessageBack(t *testing.T) {
	socketPath := refreshBroker(t, map[string]any{
		"error": map[string]any{"code": "bad_request", "message": "unknown op refresh"},
	})
	t.Setenv("FARAMIR_SOCKET", socketPath)
	if answer := tellBrokerToReRead(); answer != "unknown op refresh" {
		t.Errorf("tellBrokerToReRead = %q, want the refusal it was given", answer)
	}
}

// The three silences: nothing listening, a connection dropped before the
// answer, and an answer that is not JSON. Each is the file written and the
// broker not known to have re-read it, which is not a failure of the write.
func TestABrokerThatDidNotAnswerIsNotARefusal(t *testing.T) {
	t.Run("nothing is listening", func(t *testing.T) {
		t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
		if answer := tellBrokerToReRead(); answer != "" {
			t.Errorf("tellBrokerToReRead = %q, want silence", answer)
		}
	})
	t.Run("the connection is dropped unanswered", func(t *testing.T) {
		t.Setenv("FARAMIR_SOCKET", refreshBroker(t, nil))
		if answer := tellBrokerToReRead(); answer != "" {
			t.Errorf("tellBrokerToReRead = %q, want silence", answer)
		}
	})
	t.Run("the answer will not parse", func(t *testing.T) {
		socketPath := filepath.Join(t.TempDir(), "b.sock")
		listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer func() { _ = conn.Close() }()
			if _, err := sockutil.ReadLine(conn, 1<<20); err != nil {
				return
			}
			_, _ = conn.Write([]byte("not json\n"))
		}()
		t.Setenv("FARAMIR_SOCKET", socketPath)
		if answer := tellBrokerToReRead(); answer != "" {
			t.Errorf("tellBrokerToReRead = %q, want silence", answer)
		}
	})
}

// The sentence stands next to "wrote the file", so each of the three answers
// has to read as a different state of the value: covered, not known to be
// covered, and refused with the reason.
func TestTheNoteSaysWhetherTheValueIsCoveredYet(t *testing.T) {
	const waiting = "it picks this up within one refresh interval"
	for _, tc := range []struct {
		name, answer string
		says         []string
	}{
		{"the broker re-read it", reReadOK, []string{"has re-read it"}},
		{"the broker did not answer", "", []string{"did not answer", waiting}},
		{"the broker refused", "unknown op refresh",
			[]string{"refused", "unknown op refresh", waiting}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			note := reReadNote(tc.answer, waiting)
			for _, want := range tc.says {
				if !strings.Contains(note, want) {
					t.Errorf("note = %q, want it to say %q", note, want)
				}
			}
		})
	}
}
