package ptyutil

import (
	"errors"
	"os"
	"testing"
	"time"
)

// A read deadline on the master has to fire. The caller polls the master with
// a one-second deadline so it can notice a run it should stop, and every ioctl
// here is routed through SyscallConn to keep that working: File.Fd takes the
// file out of the runtime's poller for good, and SetReadDeadline is then
// accepted and silently never fires. Nothing about the output would change, so
// the loss shows up only as a timeout that does not happen.
func TestAReadDeadlineOnTheMasterFires(t *testing.T) {
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	SetWinsize(master, 40, 120)

	if err := master.SetReadDeadline(time.Now().Add(200 * time.Millisecond)); err != nil {
		t.Fatalf("the master takes no read deadline: %v", err)
	}
	started := time.Now()
	buf := make([]byte, 64)
	// Nothing has been written to the slave, so this can only end on the
	// deadline.
	_, err = master.Read(buf)
	waited := time.Since(started)

	if !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("read of a quiet pty returned %v after %v, want a deadline", err, waited)
	}
	if waited > 5*time.Second {
		t.Errorf("the deadline took %v to fire", waited)
	}
}

// And the pair still carries what is written through it, the deadline being
// the only thing the routing above was meant to change.
func TestThePairCarriesWhatIsWrittenToIt(t *testing.T) {
	master, slave, err := Open()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = master.Close(); _ = slave.Close() })
	SetWinsize(master, 40, 120)

	if _, err := slave.WriteString("hello\n"); err != nil {
		t.Fatal(err)
	}
	if err := master.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	n, err := master.Read(buf)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	// The line discipline turns the newline into CRLF, which is what a caller
	// reading a terminal gets.
	if got := string(buf[:n]); got != "hello\r\n" {
		t.Errorf("read %q, want the line that was written", got)
	}
}
