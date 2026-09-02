package sockutil

import (
	"errors"
	"net"
	"strings"
	"testing"
)

// -- the request limit ------------------------------------------------------

// pipeWriting returns the reading end of a pipe with body already on its way.
func pipeWriting(t *testing.T, body string) net.Conn {
	t.Helper()
	writer, reader := net.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	go func() {
		_, _ = writer.Write([]byte(body))
		_ = writer.Close()
	}()
	return reader
}

// the request cap bounds what an unauthenticated read allocates.
// ErrTooLarge rather than a short line: the broker answers with too_large,
// where a truncated line would parse as a malformed request.
func TestReadLineRefusesALineOverTheLimit(t *testing.T) {
	_, err := ReadLine(pipeWriting(t, strings.Repeat("x", 200)+"\n"), 64)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestReadLineReturnsALineInsideTheLimit(t *testing.T) {
	line, err := ReadLine(pipeWriting(t, "{\"op\":\"status\"}\nsecond line\n"), 64)
	if err != nil {
		t.Fatal(err)
	}
	// The first line only, without its newline.
	if string(line) != `{"op":"status"}` {
		t.Errorf("line = %q", line)
	}
}

// The CLI closes its write half rather than terminating the line, so refusing
// this would refuse every call it makes.
func TestReadLineAcceptsALineEndedByEOF(t *testing.T) {
	line, err := ReadLine(pipeWriting(t, `{"op":"status"}`), 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != `{"op":"status"}` {
		t.Errorf("line = %q", line)
	}
}
