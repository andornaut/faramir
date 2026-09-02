package sockutil

// Reading a stream of payloads.

import (
	"errors"
	"strings"
	"testing"
)

// LineReader keeps whatever a read pulled in past the newline, so successive
// payloads all arrive. ReadLine keeps no buffer and drops it, which is why a
// stream uses this rather than calling ReadLine twice.
func TestALineReaderReturnsEveryPayload(t *testing.T) {
	reader := NewLineReader(pipeWriting(t, "first\nsecond\nthird\n"), 64)
	for _, want := range []string{"first", "second", "third"} {
		line, err := reader.Next()
		if err != nil {
			t.Fatalf("reading %q: %v", want, err)
		}
		if string(line) != want {
			t.Errorf("payload = %q, want %q", line, want)
		}
	}
}

// The same contract ReadLine has at the edges, so the broker answers a stream's
// chunks and a lone request identically.
func TestALineReaderKeepsReadLinesContract(t *testing.T) {
	if _, err := NewLineReader(pipeWriting(t, strings.Repeat("x", 200)+"\n"), 64).Next(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a payload over the limit: err = %v, want ErrTooLarge", err)
	}
	// The CLI closes its write half rather than terminating the last line.
	line, err := NewLineReader(pipeWriting(t, `{"op":"status"}`), 64).Next()
	if err != nil || string(line) != `{"op":"status"}` {
		t.Errorf("a payload ended by EOF: %q, %v", line, err)
	}
	// A peer that sends only whitespace and closes is nothing usable: nil and no
	// error, rather than an empty payload for the caller to try to parse.
	if line, err := NewLineReader(pipeWriting(t, "   "), 64).Next(); err != nil || line != nil {
		t.Errorf("whitespace then EOF: %q, %v", line, err)
	}
}

// A payload longer than the buffer arrives in pieces and must be rejoined.
func TestALineReaderRejoinsAPayloadLongerThanItsBuffer(t *testing.T) {
	body := strings.Repeat("y", 40000)
	reader := NewLineReader(pipeWriting(t, body+"\nnext\n"), 1<<20)
	line, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != body {
		t.Errorf("payload is %d bytes, want %d", len(line), len(body))
	}
	if line, err = reader.Next(); err != nil || string(line) != "next" {
		t.Errorf("the payload after a long one = %q, %v", line, err)
	}
}
