package executor

import (
	"errors"
	"fmt"
	"strings"
	"testing"
	"unicode/utf8"
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

func TestAppendOutputStopsAtTheLimitAndSaysSo(t *testing.T) {
	for _, tc := range []struct {
		name          string
		text          string
		emitted       int
		limit         int
		truncated     bool
		wantEmitted   int
		wantTruncated bool
		wantWritten   string
	}{
		{"under the limit is written whole", "abc", 0, 10, false, 3, false, "abc"},
		{"exactly the limit is not truncation", "abcde", 0, 5, false, 5, false, "abcde"},
		{"over the limit keeps what fits", "abcdef", 0, 3, false, 3, true, "abc"},
		{"no room left writes only the notice", "abc", 5, 5, false, 5, true, ""},
		{"already truncated writes nothing", "abc", 5, 10, true, 5, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var b strings.Builder
			emitted, truncated := appendOutput(&b, tc.text, tc.emitted, tc.limit, tc.truncated)
			if emitted != tc.wantEmitted || truncated != tc.wantTruncated {
				t.Errorf("got (%d, %v), want (%d, %v)",
					emitted, truncated, tc.wantEmitted, tc.wantTruncated)
			}
			got := b.String()
			notice := fmt.Sprintf("\n[faramir] output truncated at %d bytes\n", tc.limit)
			if tc.wantTruncated && !tc.truncated {
				if !strings.HasSuffix(got, notice) {
					t.Errorf("truncated output does not say so: %q", got)
				}
				got = strings.TrimSuffix(got, notice)
			}
			if got != tc.wantWritten {
				t.Errorf("wrote %q, want %q", got, tc.wantWritten)
			}
		})
	}
}

// Truncation is sticky: once the cap is reached the caller keeps draining the
// PTY so the child does not block, and none of what it drains is kept.
func TestAppendOutputStaysTruncatedOnceItIs(t *testing.T) {
	var b strings.Builder
	emitted, truncated := appendOutput(&b, strings.Repeat("x", 50), 0, 10, false)
	if !truncated {
		t.Fatal("50 bytes into a 10-byte limit did not truncate")
	}
	before := b.Len()
	for range 5 {
		emitted, truncated = appendOutput(&b, "more output", emitted, 10, truncated)
	}
	if !truncated || emitted != 10 {
		t.Errorf("emitted=%d truncated=%v after further writes, want 10 and true", emitted, truncated)
	}
	if b.Len() != before {
		t.Errorf("%d bytes were written after truncation", b.Len()-before)
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
