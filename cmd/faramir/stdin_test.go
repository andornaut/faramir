package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"
)

// -i is what says the input is meant for the command. Without it a pipeline is
// refused rather than dropped, and every other stdin is left alone: a `while
// read` loop and an ssh session both hand this process a file they are still
// using, and reading either would take input away from its owner.
func TestAPipelineWithoutTheFlagIsRefusedAndNothingElseIsRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	// Written and closed: a reader waits for the end of a pipe, and a writer
	// left open is a test that hangs rather than one that fails.
	if _, err := writer.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = saved }()

	if _, err := pipedStdin(false); err == nil {
		t.Error("a pipeline with no -i was accepted, so the input reaches nothing " +
			"and nobody is told")
	}
	piped, err := pipedStdin(true)
	if err != nil {
		t.Fatalf("-i refused a pipeline: %v", err)
	}
	if string(piped) != "x" {
		t.Errorf("-i read %q, want the piped byte", piped)
	}

	// A regular file is one this process does not own: read here, the loop that
	// opened it gets nothing.
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	os.Stdin = file
	if _, err := pipedStdin(false); err != nil {
		t.Errorf("an inherited file was refused, and no pipeline was there to send: %v", err)
	}
	if at, err := file.Seek(0, io.SeekCurrent); err != nil || at != 0 {
		t.Errorf("the file was read to offset %d, so the caller that opened it lost that much", at)
	}
}

// The pipe a subprocess inherits once its parent is done with it: empty, and
// with no writer left to fill it. Refusing that is refusing a run over an
// input that does not exist, which is what a program driving faramir through a
// subprocess hands it whether or not anybody meant to pipe anything.
//
// The pipe a producer has yet to write to is not distinguishable from one it
// is about to write to, so it stays refused.
func TestAPipeNothingCanArriveOnIsNotAPipeline(t *testing.T) {
	saved := os.Stdin
	defer func() { os.Stdin = saved }()

	spent, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = spent.Close() }()
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	os.Stdin = spent
	if _, err := pipedStdin(false); err != nil {
		t.Errorf("a pipe every writer had closed with nothing in it was refused, "+
			"and no input was there to send: %v", err)
	}

	open, held, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = open.Close() }()
	defer func() { _ = held.Close() }()
	os.Stdin = open
	if _, err := pipedStdin(false); err == nil {
		t.Error("a pipe whose writer is still there was accepted, so what it " +
			"sends reaches nothing and nobody is told")
	}
}

// A FIFO is S_IFIFO and hangs up exactly as an anonymous pipe does, and is not
// the same thing: another writer may open it after the last one closed, so what
// a hangup says there is that nothing has arrived yet. Taking it for spent
// would drop what that writer sends, which is the silence -i exists to remove.
func TestASpentFIFOIsStillAPipeline(t *testing.T) {
	saved := os.Stdin
	defer func() { os.Stdin = saved }()

	path := filepath.Join(t.TempDir(), "fifo")
	if err := unix.Mkfifo(path, 0o600); err != nil {
		t.Fatal(err)
	}
	// Non-blocking, or the read end waits for the writer opened on the next
	// line, which is waiting for this one.
	fd, err := unix.Open(path, unix.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		t.Fatal(err)
	}
	reader := os.NewFile(uintptr(fd), path)
	defer func() { _ = reader.Close() }()

	// Opened and closed with nothing sent, which is the state an anonymous pipe
	// is let through in: POLLHUP with no POLLIN.
	writer, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}

	os.Stdin = reader
	if _, err := pipedStdin(false); err == nil {
		t.Error("a FIFO whose writer had closed was taken for spent, so what the " +
			"next writer opens it to send reaches nothing and nobody is told")
	}
}
