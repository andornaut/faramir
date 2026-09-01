package main

import (
	"os"
	"testing"

	"github.com/andornaut/faramir/internal/termui"
)

// captureStdout runs fn with stdout on a pipe and returns what it wrote.
func captureStdout(t *testing.T, fn func() int) (string, int) {
	t.Helper()
	return captureFile(t, &os.Stdout, fn)
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

// plain is colour off, so the assertions are about content rather than escapes.
func plain(t *testing.T) termui.Palette {
	t.Helper()
	return mustPalette(t, "never")
}

func mustPalette(t *testing.T, when string) termui.Palette {
	t.Helper()
	paint, err := termui.NewPalette(when)
	if err != nil {
		t.Fatal(err)
	}
	return paint
}

func always(t *testing.T) termui.Palette {
	t.Helper()
	return mustPalette(t, "always")
}
