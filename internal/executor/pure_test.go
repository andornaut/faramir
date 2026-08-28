package executor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/execserver"
)

// The output path's byte handling, tested directly. Run() needs a PTY and a
// delegated cgroup and skips without one; these need neither, so the rune and
// truncation rules are checked on every host.

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

// Anything not valid on its own is held back for the next read, whether or not
// more bytes could complete it. Run flushes the remainder after the loop, so
// holding back a byte that never becomes valid costs a read, not output.
func TestDecodeUTF8HoldsBackWhatIsNotYetValid(t *testing.T) {
	for _, tc := range []struct {
		name          string
		b             string
		wantText      string
		wantRemainder string
	}{
		{"all ascii", "hello", "hello", ""},
		{"empty", "", "", ""},
		{"a whole multi-byte rune", "hé", "hé", ""},
		{"a two-byte rune cut in half", "h\xc3", "h", "\xc3"},
		{"a three-byte rune cut short", "a\xe2\x82", "a", "\xe2\x82"},
		{"a four-byte rune cut short", "a\xf0\x9d\x84", "a", "\xf0\x9d\x84"},
		{"a trailing byte that cannot start a rune is held back", "a\xff", "a", "\xff"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			text, rest := decodeUTF8([]byte(tc.b))
			if text != tc.wantText || string(rest) != tc.wantRemainder {
				t.Errorf("decodeUTF8(%q) = (%q, %q), want (%q, %q)",
					tc.b, text, rest, tc.wantText, tc.wantRemainder)
			}
		})
	}
}

// Nothing may be lost between the two returns: the remainder is carried into the
// next read, so a byte dropped here never reaches the output at all.
func TestDecodeUTF8LosesNothing(t *testing.T) {
	const full = "aé€𝄞\xffz"
	for i := 0; i <= len(full); i++ {
		text, rest := decodeUTF8([]byte(full[:i]))
		if got := text + string(rest); got != full[:i] {
			t.Errorf("decodeUTF8(%q) round-trips to %q", full[:i], got)
		}
	}
}

func TestOutputUnderTheCapIsKeptWhole(t *testing.T) {
	b := newOutputBuffer(1024)
	b.add("abc")
	b.add("def")
	got, truncated := b.result()
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
	b := newOutputBuffer(4096)
	b.add("START-OF-THE-RUN\n")
	for i := range 500 {
		b.add(fmt.Sprintf("line %d of noise ....................\n", i))
	}
	b.add("FATAL: the thing that actually went wrong\n")

	got, truncated := b.result()
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
	b := newOutputBuffer(budget)
	for range 10_000 {
		b.add(strings.Repeat("x", 64))
	}
	got, truncated := b.result()
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
	b := newOutputBuffer(512)
	b.add("head")
	b.add(strings.Repeat("a", 4000) + "THE-VERY-END")
	got, truncated := b.result()
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
	b := newOutputBuffer(256)
	for range 200 {
		b.add("héllo wörld ")
	}
	got, _ := b.result()
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

func TestIsEIORecognisesAClosedTerminal(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"nil is not EIO", nil, false},
		{"the read error a closed PTY gives", errors.New("read /dev/ptmx: input/output error"), true},
		{"any other error", errors.New("permission denied"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := isEIO(tc.err); got != tc.want {
				t.Errorf("isEIO(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

func TestRound3RoundsToMilliseconds(t *testing.T) {
	for _, tc := range []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1.0004, 1.0},
		{1.0005, 1.001},
		{1.9999, 2.0},
		{12.3456, 12.346},
	} {
		t.Run(fmt.Sprint(tc.in), func(t *testing.T) {
			if got := round3(tc.in); got != tc.want {
				t.Errorf("round3(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// exitStatus is reached only after the command ran and its output was
// collected. A missing or late executor status must not discard that: it
// becomes a kill code, never a fabricated success, and never an error that
// reads as a run that never happened.
func TestExitStatusPreservesAFinishedRun(t *testing.T) {
	if code, timedOut, unknown := exitStatus(&execserver.ChildResult{ExitCode: 42}, nil, false); code != 42 || timedOut || unknown {
		t.Errorf("reported status: code=%d timedOut=%v unknown=%v, want 42/false/false", code, timedOut, unknown)
	}
	// The whole budget elapsed with no status: the run overran the backstop and
	// was killed, which is a timeout.
	if code, timedOut, unknown := exitStatus(nil, errors.New("executor closed the connection"), true); code != 128+9 || !timedOut || unknown {
		t.Errorf("deadline-passed status: code=%d timedOut=%v unknown=%v, want 137/true/false", code, timedOut, unknown)
	}
	// The executor vanished before the deadline while the command had already
	// run: the status is unknowable, marked as such, output still returned.
	if code, timedOut, unknown := exitStatus(nil, errors.New("executor restarted"), false); code != 128+9 || timedOut || !unknown {
		t.Errorf("lost-status status: code=%d timedOut=%v unknown=%v, want 137/false/true", code, timedOut, unknown)
	}
}
