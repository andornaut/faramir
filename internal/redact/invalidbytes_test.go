package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// The count is what tells a corrupted archive from one the command meant to
// write: an invalid byte becomes U+FFFD on the way through, and after that
// nothing in the output says whether the command wrote it. Counted at the
// boundary, before the conversion, which is the last moment the two can be
// told apart.
func TestInvalidBytesAreCountedBeforeTheyBecomeReplacements(t *testing.T) {
	for _, tc := range []struct {
		name string
		text string
		want int
	}{
		{"text", "ordinary output\n", 0},
		// Valid UTF-8 that happens to be a replacement character. The command
		// wrote it, so nothing here was lost and the count stays at zero.
		{"a replacement character the command wrote", "before � after", 0},
		{"two bytes that begin no rune", "before \xff\xfe after", 2},
		// A truncated multi-byte sequence, which is what a binary read cut at a
		// chunk boundary looks like.
		{"a truncated sequence", "before \xe2\x82 after", 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(nil, DefaultPolicy())
			out := r.RedactText(tc.text)
			if got := r.InvalidBytes(); got != tc.want {
				t.Errorf("InvalidBytes() = %d, want %d", got, tc.want)
			}
			// Whatever the count, what comes out is text: an invalid byte is
			// replaced rather than passed through to whatever reads this next.
			if !utf8.ValidString(out) {
				t.Errorf("an invalid byte reached the output: %q", out)
			}
		})
	}
}

// Fed in pieces, and the count is of everything fed: the caller reports one
// number for the whole stream, so a chunk that carried nothing invalid must not
// clear what an earlier one counted.
func TestTheCountCoversTheWholeStream(t *testing.T) {
	r := New(nil, DefaultPolicy())
	r.Feed("clean\n")
	r.Feed("\xff more\n")
	r.Feed("clean again\n")
	r.Flush()

	if got := r.InvalidBytes(); got != 1 {
		t.Errorf("InvalidBytes() = %d, want 1", got)
	}
}

// A CRLF split across two reads is one line ending, not a stray carriage
// return: the first chunk ends on the \r and the pair is only recognisable once
// the second arrives. Holding the \r back is what makes the two chunks read
// like the one text they were.
func TestACarriageReturnHeldAtAChunkBoundaryIsStillNormalised(t *testing.T) {
	r := New(nil, DefaultPolicy())
	var out strings.Builder
	out.WriteString(r.Feed("first line\r"))
	out.WriteString(r.Feed("\nsecond line\r\n"))
	out.WriteString(r.Flush())

	if got := out.String(); strings.Contains(got, "\r") {
		t.Errorf("a carriage return survived: %q", got)
	} else if got != "first line\nsecond line\n" {
		t.Errorf("out = %q, want the two lines joined by one newline", got)
	}
}

// One value under two refs is one entry. Every entry runs its own pattern over
// every chunk, so a store that names the same value twice would double the work
// of the whole pass; the second would also match nothing, the first having
// already replaced it, which leaves a token nobody can account for.
func TestOneValueUnderTwoRefsIsCompiledOnce(t *testing.T) {
	const value = "hunter2-correct-horse"
	r := New([]Secret{{Ref: "first/ref", Value: value}, {Ref: "second/ref", Value: value}},
		DefaultPolicy())

	if len(r.entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(r.entries))
	}
	out := r.RedactText("value: " + value + "\n")
	if strings.Contains(out, value) {
		t.Errorf("the value survived: %q", out)
	}
	if !strings.Contains(out, TokenFor("first/ref")) {
		t.Errorf("out = %q, want the token of the ref that claimed the value first", out)
	}
	if summary := r.Summary(); len(summary) != 1 || summary[0].Count != 1 {
		t.Errorf("Summary() = %+v, want one token counted once", summary)
	}
}

// A value the policy refuses is carried by neither ref: New drops it before it
// is compiled, so nothing in the output is replaced on its account.
func TestARefusedValueCompilesToNothing(t *testing.T) {
	r := New([]Secret{{Ref: "short/ref", Value: "abc"}}, DefaultPolicy())

	if len(r.entries) != 0 {
		t.Fatalf("entries = %d, want none", len(r.entries))
	}
	if out := r.RedactText("value: abc\n"); out != "value: abc\n" {
		t.Errorf("out = %q, want the text unchanged", out)
	}
	if summary := r.Summary(); len(summary) != 0 {
		t.Errorf("Summary() = %+v, want nothing counted", summary)
	}
}
