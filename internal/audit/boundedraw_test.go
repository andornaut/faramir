package audit

// The raw-byte instantiation of Bounded, which caps the executor's response:
// the same ring the Collector runs in encoded bytes, so the properties are
// asserted against both measures.

import (
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
)

// rawMarker stands in for the executor's own, which carries the phrase these
// assertions look for.
func rawMarker(dropped int) string {
	return fmt.Sprintf("\n[%d bytes of output dropped]\n", dropped)
}

func TestCutAtRuneKeepsWholeRunesWithinTheLimit(t *testing.T) {
	for _, tc := range []struct {
		name  string
		s     string
		limit int
		want  string
	}{
		{"limit past the end returns everything", "hello", 99, "hello"},
		{"limit at the end returns everything", "hello", 5, "hello"},
		{"ascii cuts exactly", "hello", 3, "hel"},
		{"zero limit returns nothing", "hello", 0, ""},
		{"negative limit returns nothing", "hello", -1, ""},
		{"a split two-byte rune is dropped whole", "hé", 2, "h"},
		{"a whole two-byte rune is kept", "hé", 3, "hé"},
		{"a split three-byte rune is dropped whole", "a€", 3, "a"},
		{"a whole three-byte rune is kept", "a€", 4, "a€"},
		{"a split four-byte rune is dropped whole", "a𝄞", 4, "a"},
		{"a whole four-byte rune is kept", "a𝄞", 5, "a𝄞"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := cutAtRune(tc.s, tc.limit); got != tc.want {
				t.Errorf("cutAtRune(%q, %d) = %q, want %q", tc.s, tc.limit, got, tc.want)
			}
		})
	}
}

// A PTY hands over whatever the child wrote, so a chunk can be invalid at any
// offset. Backing off to the last valid prefix would drop every byte after the
// first bad one; the rule is to back off far enough for a partial rune and no
// further.
func TestCutAtRuneDoesNotDropTheTailAfterAnInvalidByte(t *testing.T) {
	s := "\xffgood text after an invalid byte"
	got := cutAtRune(s, 20)
	if len(got) < 15 {
		t.Errorf("cutAtRune dropped the tail after an invalid byte: %q", got)
	}
	if !strings.Contains(got, "good text") {
		t.Errorf("the valid text after the invalid byte did not survive: %q", got)
	}
}

// The two properties the caller relies on, over every prefix of a mixed string.
func TestCutAtRuneNeverExceedsTheLimitOrSplitsARune(t *testing.T) {
	const s = "aé€𝄞\xffz aé€𝄞 tail"
	for limit := -2; limit <= len(s)+2; limit++ {
		got := cutAtRune(s, limit)
		if limit > 0 && len(got) > limit {
			t.Fatalf("cutAtRune(_, %d) returned %d bytes", limit, len(got))
		}
		if !strings.HasPrefix(s, got) {
			t.Fatalf("cutAtRune(_, %d) = %q, which is not a prefix of the input", limit, got)
		}
		// Whatever it returns must not end mid-rune, unless the input itself was
		// invalid there: a trailing partial rune is what this exists to prevent.
		if r, size := utf8.DecodeLastRuneInString(got); r == utf8.RuneError && size == 1 {
			if utf8.ValidString(s[:len(got)]) {
				t.Fatalf("cutAtRune(_, %d) = %q ends on a partial rune", limit, got)
			}
		}
	}
}

func TestOutputUnderTheCapIsKeptWhole(t *testing.T) {
	b := NewBounded(1024, Raw)
	b.Add("abc")
	b.Add("def")
	got, dropped := b.Result(rawMarker)
	truncated := dropped > 0
	if truncated {
		t.Error("six bytes into a 1 KiB cap reported truncation")
	}
	if got != "abcdef" {
		t.Errorf("got %q, want the whole of what was written", got)
	}
}

// The regression this shape exists to prevent: a command that prints for a
// long time and then says why it failed. Keeping the head alone returned the
// first half of the noise and none of the reason, and the exit code was the
// only sign anything had gone wrong.
func TestTheEndOfALongOutputSurvives(t *testing.T) {
	b := NewBounded(4096, Raw)
	b.Add("START-OF-THE-RUN\n")
	for i := range 500 {
		b.Add(fmt.Sprintf("line %d of noise ....................\n", i))
	}
	b.Add("FATAL: the thing that actually went wrong\n")

	got, dropped := b.Result(rawMarker)
	truncated := dropped > 0
	if !truncated {
		t.Fatal("far past the cap did not report truncation")
	}
	if !strings.Contains(got, "FATAL: the thing that actually went wrong") {
		t.Error("the end of the output did not survive, which is what it is read for")
	}
	if !strings.Contains(got, "START-OF-THE-RUN") {
		t.Error("the start of the output did not survive")
	}
	if !strings.Contains(got, "bytes of output dropped") {
		t.Errorf("nothing says output was dropped: %q", got[:min(200, len(got))])
	}
}

// A run that never stops printing is held in the broker's memory while it runs,
// so what it costs has to be the cap rather than what it wrote.
func TestAChattyRunStaysBounded(t *testing.T) {
	const budget = 2048
	b := NewBounded(budget, Raw)
	for range 10_000 {
		b.Add(strings.Repeat("x", 64))
	}
	got, dropped := b.Result(rawMarker)
	truncated := dropped > 0
	if !truncated {
		t.Fatal("640 KiB into a 2 KiB cap did not truncate")
	}
	if len(got) > budget {
		t.Errorf("kept %d bytes against a %d byte cap", len(got), budget)
	}
	if b.tailLen > b.half() {
		t.Errorf("the tail holds %d bytes against a half of %d", b.tailLen, b.half())
	}
}

// One chunk larger than the whole tail budget: its own tail is what is kept, so
// a single enormous write does not cost the end of the output either.
func TestOneOversizedChunkKeepsItsOwnTail(t *testing.T) {
	b := NewBounded(512, Raw)
	b.Add("head")
	b.Add(strings.Repeat("a", 4000) + "THE-VERY-END")
	got, dropped := b.Result(rawMarker)
	truncated := dropped > 0
	if !truncated {
		t.Fatal("4 KiB into a 512 byte cap did not truncate")
	}
	if !strings.HasSuffix(got, "THE-VERY-END") {
		t.Errorf("the end of an oversized chunk was dropped: %q", got[max(0, len(got)-40):])
	}
}

// Both cuts land on rune boundaries, or the output carries a partial rune the
// caller has to render.
func TestNeitherCutSplitsARune(t *testing.T) {
	b := NewBounded(256, Raw)
	for range 200 {
		b.Add("héllo wörld ")
	}
	got, _ := b.Result(rawMarker)
	if !utf8.ValidString(got) {
		t.Error("the kept output is not valid UTF-8, so a cut split a rune")
	}
}

func TestTailAtRuneOpensOnAWholeRune(t *testing.T) {
	const s = "héllo"
	for limit := 1; limit <= len(s)+2; limit++ {
		got := tailAtRune(s, limit)
		if !utf8.ValidString(got) {
			t.Errorf("tailAtRune(%q, %d) = %q, which is not valid UTF-8", s, limit, got)
		}
		if !strings.HasSuffix(s, got) {
			t.Errorf("tailAtRune(%q, %d) = %q, which is not a suffix of it", s, limit, got)
		}
		if len(got) > limit {
			t.Errorf("tailAtRune(%q, %d) kept %d bytes", s, limit, len(got))
		}
	}
}
