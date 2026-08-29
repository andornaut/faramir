package redact

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// chunks splits text into pieces at the offsets the seed picks, on rune
// boundaries: a byte-offset split would cut a multi-byte character in half,
// which is a different property from the one this is about.
func chunks(text string, seed []byte) []string {
	runes := []rune(text)
	if len(runes) == 0 || len(seed) == 0 {
		return []string{text}
	}
	var out []string
	at := 0
	for _, b := range seed {
		if at >= len(runes) {
			break
		}
		step := int(b)%len(runes) + 1
		end := min(at+step, len(runes))
		out = append(out, string(runes[at:end]))
		at = end
	}
	if at < len(runes) {
		out = append(out, string(runes[at:]))
	}
	return out
}

// stream feeds the pieces through a redactor and returns everything it emitted.
func stream(r *Redactor, pieces []string) string {
	var b strings.Builder
	for _, p := range pieces {
		b.WriteString(r.Feed(p))
	}
	b.WriteString(r.Flush())
	return b.String()
}

// The property the whole package exists for: no rendering of a value the
// redactor holds reaches the output, whatever the text around it and wherever
// the chunk breaks land.
//
// Values whose own bytes stage 1 rewrites are out of scope here and covered by
// their own test: this hunts for the other ways a value gets through.
func FuzzNoRenderingOfAValueSurvives(f *testing.F) {
	f.Add("hunter2-correct-horse", "before ", " after", []byte{3, 7})
	f.Add("Aa0!$&/=?-_.~ ", "x", "y", []byte{1, 1, 1})
	f.Add("////////", "", "", []byte{2})
	f.Add("aaaaaaaa", "aaaa", "aaaa", []byte{5})

	f.Fuzz(func(t *testing.T, value, prefix, suffix string, seed []byte) {
		// A value that is not valid UTF-8, and one whose own bytes stage 1
		// rewrites, are their own cases and are skipped here so this keeps
		// hunting for the ways a value gets past the matcher itself.
		if DefaultPolicy().Check(value) != "" || stripANSI(value) != value || !utf8.ValidString(value) {
			t.Skip()
		}
		if !isPrintableRun(value) {
			t.Skip()
		}
		for rendering := range variants(value) {
			if stripANSI(rendering) != rendering || len([]rune(rendering)) < 8 {
				continue
			}
			text := prefix + rendering + suffix
			r := New([]Secret{{Ref: "a/b", Value: value}}, DefaultPolicy())
			got := stream(r, chunks(text, seed))
			if strings.Contains(got, rendering) {
				t.Fatalf("rendering %q survived in %q (value %q, chunks %v)",
					rendering, got, value, chunks(text, seed))
			}
		}
	})
}

// isPrintableRun keeps the corpus to values a credential could be: the point of
// the target above is the matcher, not stage 1's treatment of odd bytes.
func isPrintableRun(v string) bool {
	for _, r := range v {
		if r < 0x20 || r == 0x7f {
			return false
		}
	}
	return true
}

// Where the chunk breaks fall is the client's business, so the same bytes have
// to come back the same way however they were cut. A difference here is a value
// caught on one chunking and missed on another, or output the stream ate.
func FuzzTheChunkingDoesNotChangeTheOutput(f *testing.F) {
	f.Add("hunter2-correct-horse", "a hunter2-correct-horse b", []byte{1, 2, 3})
	f.Add("hunter2-correct-horse", "\x1b[31mhunter2-correct-horse\x1b[0m", []byte{4})
	f.Add("hunter2-correct-horse", "line\r\nhunter2-correct-horse\r\n", []byte{2, 2})

	f.Fuzz(func(t *testing.T, value, text string, seed []byte) {
		if DefaultPolicy().Check(value) != "" || !utf8.ValidString(value) {
			t.Skip()
		}
		one := New([]Secret{{Ref: "a/b", Value: value}}, DefaultPolicy())
		want := one.RedactText(text)
		many := New([]Secret{{Ref: "a/b", Value: value}}, DefaultPolicy())
		got := stream(many, chunks(text, seed))
		if got != want {
			t.Fatalf("chunked %q, one-shot %q (value %q, chunks %q)", got, want, value, chunks(text, seed))
		}
	})
}

// Two secrets, one a substring of the other: whichever token wins, neither
// value may be left in the output.
func FuzzNeitherOfTwoOverlappingValuesSurvives(f *testing.F) {
	f.Add("hunter2-correct", "hunter2-correct-horse", "x ", " y", []byte{3})

	f.Fuzz(func(t *testing.T, short, long, prefix, suffix string, seed []byte) {
		p := DefaultPolicy()
		if p.Check(short) != "" || p.Check(long) != "" {
			t.Skip()
		}
		if !utf8.ValidString(short) || !utf8.ValidString(long) {
			t.Skip()
		}
		if !isPrintableRun(short) || !isPrintableRun(long) {
			t.Skip()
		}
		for _, text := range []string{prefix + short + suffix, prefix + long + suffix} {
			got := stream(New([]Secret{{Ref: "a/short", Value: short}, {Ref: "b/long", Value: long}}, p),
				chunks(text, seed))
			if strings.Contains(got, short) || strings.Contains(got, long) {
				t.Fatalf("a value survived: %q from %q", got, text)
			}
		}
	})
}
