package termsafe

import (
	"strings"
	"testing"
	"unicode/utf8"
)

// Nothing termsafe renders may still be able to act on a terminal: it is the
// last thing between a command's output and the operator's screen.
func FuzzNothingActionableReachesATerminal(f *testing.F) {
	f.Add("plain text")
	f.Add("\x1b[31mred\x1b[0m")
	f.Add("\x07\x08\x0c\x7f")

	f.Fuzz(func(t *testing.T, text string) {
		// A tab is left as it was written, which is what unsafeRune says and what
		// Line documents; everything else a terminal acts on is escaped.
		for _, got := range []string{Line(text), Arg(text), Field(text, 64)} {
			for _, r := range got {
				if r != '\t' && Actionable(r) {
					t.Fatalf("an actionable rune survived: %q in %q (from %q)", r, got, text)
				}
			}
			if !utf8.ValidString(got) {
				t.Fatalf("rendered text is not valid UTF-8: %q (from %q)", got, text)
			}
		}
	})
}

// Bound and Field are what keep one long line from filling the screen, so a
// limit they are given bounds what they return.
func FuzzTheLimitIsKept(f *testing.F) {
	f.Add("some text", 8)
	f.Add(strings.Repeat("e", 200), 12)

	f.Fuzz(func(t *testing.T, text string, limit int) {
		if limit < 1 || limit > 1<<16 {
			t.Skip()
		}
		for _, got := range []string{Bound(text, limit), Field(text, limit)} {
			if len([]rune(got)) > limit*8+64 {
				t.Fatalf("a limit of %d produced %d runes: %q", limit, len([]rune(got)), got)
			}
		}
	})
}
