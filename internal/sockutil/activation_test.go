package sockutil

import (
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// Socket activation, which is how every daemon here gets its listener on a real
// host: systemd binds the socket, passes the descriptor, and names the pid it
// passed it to. The pid is the whole of what makes the variables ours: they are
// inherited by every child, so a process that read them without checking would
// take its parent's socket as its own.
func TestListenTakesTheSystemdSocketOnlyWhenItWasPassedToThisProcess(t *testing.T) {
	// A path to fall back to, so a case that does not take the passed socket
	// still ends with a listener rather than an error about the directory.
	path := filepath.Join(t.TempDir(), "b.sock")

	for _, tc := range []struct {
		name     string
		fds      string
		pid      string
		selfBind bool // ends up binding its own rather than erroring
		says     string
	}{
		// Inherited from a parent that was activated: the count is set and the
		// pid is somebody else's, so the descriptor is not this process's to use.
		{name: "the variables belong to a parent", fds: "1", pid: "1", selfBind: true},
		{name: "no activation at all", fds: "", pid: "", selfBind: true},
		{name: "a count of zero", fds: "0", pid: "", selfBind: true},
		// Ours, and more than one: which of them is the socket is not stated, so
		// this refuses rather than taking the first.
		{name: "two sockets for one listener", fds: "2", pid: "self", says: "exactly 1"},
		{name: "three", fds: "3", pid: "self", says: "exactly 1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("LISTEN_FDS", tc.fds)
			pid := tc.pid
			if pid == "self" {
				pid = strconv.Itoa(os.Getpid())
			}
			t.Setenv("LISTEN_PID", pid)

			ln, err := Listen(path)
			if ln != nil {
				t.Cleanup(func() { _ = ln.Close() })
			}
			if tc.selfBind {
				if err != nil {
					t.Fatalf("bound nothing: %v", err)
				}
				if ln.Addr().String() != path {
					t.Errorf("listening on %q, want the path it was given", ln.Addr())
				}
				return
			}
			if err == nil {
				t.Fatal("took a socket without being told which one")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error %q does not say %q", err, tc.says)
			}
		})
	}
}

// A self-bound socket is created under a umask rather than chmodded afterwards:
// one created world-writable and narrowed a moment later is reachable in
// between, and what reaches it is the broker's own protocol.
func TestASelfBoundSocketIsNeverWiderThanItsFinalMode(t *testing.T) {
	t.Setenv("LISTEN_FDS", "")
	t.Setenv("LISTEN_PID", "")
	path := filepath.Join(t.TempDir(), "b.sock")
	ln, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = ln.Close() }()

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != bindMode {
		t.Errorf("mode = %04o, want %04o", got, bindMode)
	}
}

// systemd's notify socket is given in the abstract namespace as often as not,
// and the abstract form is a leading NUL that no environment variable can
// carry, so "@" is how it is written.
//
// This asserts that a daemon given that spelling reports ready, which is the
// thing worth holding. It does not assert the conversion in NotifyReady: Go's
// own unixgram dialler accepts the "@" spelling and makes the same socket, so
// the conversion is defensive rather than load-bearing and removing it changes
// nothing this or any other test could see.
func TestNotifyReadyDialsTheAbstractSocketTheAtSignStandsFor(t *testing.T) {
	name := "\x00faramir-test-notify"
	conn, err := net.ListenPacket("unixgram", name)
	if err != nil {
		t.Skipf("this host has no abstract unixgram namespace: %v", err)
	}
	defer func() { _ = conn.Close() }()

	// Written the way systemd writes it, which is the form under test.
	t.Setenv("NOTIFY_SOCKET", "@"+name[1:])
	NotifyReady()

	buf := make([]byte, 64)
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		t.Fatalf("nothing arrived on the abstract socket: %v", err)
	}
	if got := string(buf[:n]); got != "READY=1" {
		t.Errorf("received %q, want READY=1", got)
	}
}

// And no notify socket is not an error: a daemon started by hand has none, and
// reporting ready is the one thing it need not do.
func TestNotifyReadyIsQuietWithNoSocketNamed(t *testing.T) {
	t.Setenv("NOTIFY_SOCKET", "")
	NotifyReady() // must not panic or block
}
