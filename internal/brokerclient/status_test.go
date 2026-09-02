package brokerclient

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// answeringBroker answers every request with reply on a socket of its own and
// hands back the path. A nil reply closes the connection without answering,
// which is the broker restarting under the request rather than refusing it.
func answeringBroker(t *testing.T, reply any) string {
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

	if answer := Refresh(socketPath); answer != RefreshOK {
		t.Fatalf("Refresh = %q, want %q", answer, RefreshOK)
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
	socketPath := answeringBroker(t, map[string]any{
		"error": map[string]any{"code": "bad_request", "message": "unknown op refresh"},
	})
	if answer := Refresh(socketPath); answer != "unknown op refresh" {
		t.Errorf("Refresh = %q, want the refusal it was given", answer)
	}
}

// The three silences: nothing listening, a connection dropped before the
// answer, and an answer that is not JSON. Each is the file written and the
// broker not known to have re-read it, which is not a failure of the write.
func TestABrokerThatDidNotAnswerIsNotARefusal(t *testing.T) {
	t.Run("nothing is listening", func(t *testing.T) {
		if answer := Refresh(filepath.Join(t.TempDir(), "absent.sock")); answer != "" {
			t.Errorf("Refresh = %q, want silence", answer)
		}
	})
	t.Run("the connection is dropped unanswered", func(t *testing.T) {
		if answer := Refresh(answeringBroker(t, nil)); answer != "" {
			t.Errorf("Refresh = %q, want silence", answer)
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
		if answer := Refresh(socketPath); answer != "" {
			t.Errorf("Refresh = %q, want silence", answer)
		}
	})
}

// refusingBroker answers every request the way a daemon of another release
// does: the op is never read, so there is no body, and the response names the
// build that answered, which here is this one.
func refusingBroker(t *testing.T) string {
	t.Helper()
	return answeringBroker(t, protocol.ErrorResponse("bad_request", version.Mismatch("0.0.1"), ""))
}

// Skew is the one state where the broker refuses the very question that would
// report it, the version being checked before the op is read. The refusal names
// the build that answered, so it is the answer: taken any other way, `doctor`
// reports a broker that said nothing, which is a warning naming no build and is
// what a stopped install looks like.
func TestAskStatusTakesTheVersionFromARefusal(t *testing.T) {
	// The fixture answers as this build, which is what a running broker of
	// another release is to the binary asking.
	got := AskStatus(refusingBroker(t))
	if got.Version != version.Version {
		t.Errorf("AskStatus version = %q, want %q from the refusal",
			got.Version, version.Version)
	}
	// There is no status body in a refusal, so nothing may be claimed about
	// where that broker's config sits: configFileFrom reads the unit instead.
	if got.ConfigDir != "" {
		t.Errorf("AskStatus configDir = %q, want empty: a refusal carries no body",
			got.ConfigDir)
	}
}
