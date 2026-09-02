// Package testio captures what a function writes to the process's own stdout
// or stderr, for tests of code that prints rather than returns. Imported only
// from _test.go files.
//
// One copy rather than one per package that prints: the swap of a package
// variable has to be undone in every path, and a helper that leaks the pipe on
// a fatal assertion hangs the run rather than failing it.
package testio

import (
	"os"
	"testing"
)

// CaptureStdout runs fn with stdout on a pipe and returns what it wrote.
func CaptureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	return captureFile(t, &os.Stdout, fn)
}

// CaptureStderr is the same for the stream a refusal is written to.
func CaptureStderr(t *testing.T, fn func() int) (string, int) {
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
