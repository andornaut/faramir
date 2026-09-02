package termui

// The palette --color selects.

import (
	"strings"
	"testing"
)

// paletteOf is the palette --color=when selects, or a fatal test.
func paletteOf(t *testing.T, when string) Palette {
	t.Helper()
	paint, err := NewPalette(when)
	if err != nil {
		t.Fatal(err)
	}
	return paint
}

// https://no-color.org: honoured whatever its value, empty included.
func TestNoColorDisablesColourWhateverItsValue(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if paletteOf(t, "auto").on {
		t.Error("NO_COLOR set to empty did not disable colour")
	}
}

// --color=always is for piping into a pager, so it beats the terminal check.
func TestColorAlwaysBeatsTheTerminalCheck(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	paint := paletteOf(t, "always")
	if !paint.on {
		t.Error("--color=always did not force colour on")
	}
	if !strings.Contains(paint.OK("x"), "\x1b[") {
		t.Error("colour is on but nothing was emitted")
	}
}

func TestTokenHighlightsEverySecretToken(t *testing.T) {
	got := paletteOf(t, "always").Token("a «SECRET:one» b «SECRET:two» c")
	if strings.Count(got, "\x1b[35m") != 2 {
		t.Errorf("expected both tokens highlighted: %q", got)
	}
	// The surrounding text survives intact, escapes aside.
	for _, want := range []string{"a ", " b ", " c"} {
		if !strings.Contains(got, want) {
			t.Errorf("text around the tokens was lost: %q", got)
		}
	}
}

// A record truncated mid-token must come back whole rather than be swallowed by
// the search for the close.
func TestTokenLeavesAnUnterminatedTokenAlone(t *testing.T) {
	if got := paletteOf(t, "always").Token("tail «SECRET:trunc"); got != "tail «SECRET:trunc" {
		t.Errorf("token mangled an unterminated token: %q", got)
	}
}
