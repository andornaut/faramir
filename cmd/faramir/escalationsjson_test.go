package main

// The machine-readable listing, against a socket that answers the escalations op.
//
// Below requireRootToAnswer, which the cobra command applies and this does not:
// what is under test is the shape of what reaches stdout, and that is decided
// after the caller has been checked.

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/sockutil"
)

// escalationsSocket answers one escalations op with the questions given and closes.
func escalationsSocket(t *testing.T, questions []escalation.Question) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(path) })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				lines := sockutil.NewLineReader(conn, 1<<20)
				if line, err := lines.Next(); err != nil || len(line) == 0 {
					return
				}
				_ = sockutil.Send(conn, map[string]any{"questions": questions})
			}()
		}
	}()
	return path
}

// A caller parsing stdout gets a value whether or not anything is waiting, and
// reads which of the two it was off the status rather than off the array.
func TestListEscalationsAsJSONIsAnArrayEitherWay(t *testing.T) {
	t.Run("nothing waiting", func(t *testing.T) {
		out, code := captureStdout(t, func() int {
			return listEscalations(escalationsSocket(t, nil), true, palette{})
		})
		if code != 1 {
			t.Errorf("code = %d, want 1 with nothing waiting", code)
		}
		var questions []escalation.Question
		if err := json.Unmarshal([]byte(out), &questions); err != nil {
			t.Fatalf("stdout is not JSON: %q (%v)", out, err)
		}
		if len(questions) != 0 {
			t.Errorf("nothing is waiting, but the listing holds %d: %s", len(questions), out)
		}
	})

	t.Run("one waiting", func(t *testing.T) {
		socket := escalationsSocket(t, []escalation.Question{{
			ID: "9f2a1c", Cmd: "ansible-playbook site.yml", ExpiresInSec: 118,
		}})
		out, code := captureStdout(t, func() int { return listEscalations(socket, true, palette{}) })
		if code != 0 {
			t.Errorf("code = %d, want 0 with one waiting", code)
		}
		var questions []escalation.Question
		if err := json.Unmarshal([]byte(out), &questions); err != nil {
			t.Fatalf("stdout is not JSON: %q (%v)", out, err)
		}
		if len(questions) != 1 || questions[0].ID != "9f2a1c" {
			t.Fatalf("the listing does not name the question: %s", out)
		}
	})

	// A broker that could not be reached prints no listing at all: an empty array
	// there would report a host as quiet when nothing was asked.
	t.Run("no broker", func(t *testing.T) {
		out, code := captureStdout(t, func() int {
			return listEscalations(filepath.Join(t.TempDir(), "absent.sock"), true, palette{})
		})
		if code != 69 {
			t.Errorf("code = %d, want 69 with no broker", code)
		}
		if out != "" {
			t.Errorf("stdout carries a listing for a broker that was not reached: %q", out)
		}
	})
}

// captureStdout runs fn with stdout on a pipe and returns what it wrote.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	return captureFile(t, &os.Stdout, fn)
}

// captureStderr is the same for the stream a refusal is written to.
func captureStderr(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	return captureFile(t, &os.Stderr, fn)
}

// captureFile points one of the process's own streams at a pipe for the length
// of the call. Both are package variables, so the stream is named by pointer
// rather than by a flag saying which of the two was meant.
func captureFile(t *testing.T, stream **os.File, fn func() int) (string, int) {
	t.Helper()
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	saved := *stream
	*stream = writer
	done := make(chan []byte, 1)
	go func() {
		var buf []byte
		chunk := make([]byte, 4096)
		for {
			n, err := reader.Read(chunk)
			buf = append(buf, chunk[:n]...)
			if err != nil {
				break
			}
		}
		done <- buf
	}()
	code := fn()
	*stream = saved
	_ = writer.Close()
	out := <-done
	_ = reader.Close()
	return string(out), code
}
