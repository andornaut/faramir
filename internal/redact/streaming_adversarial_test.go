package redact

import (
	"encoding/hex"
	"strings"
	"testing"
)

// A second adversarial round, aimed at the streaming machine and stage-1
// stripping rather than the encoding-variant set. Three questions:
//
//   A. Does the overlap buffer hold a variant that a formatter wrapped at a
//      pathological width and that arrives one rune per Feed? (should REDACT)
//   B. Is a colour code spliced into a value stripped before matching, as the
//      doc claims? (should REDACT)
//   C. Where does stage-1 stripping actually end: what separator splits a
//      value in the matched text while a terminal collapses it? (boundary;
//      these are the deliberate class the threat model disclaims, shown to map
//      the edge, not asserted as covered)

const streamSecret = "hunter2correcthorsebatteryZ9"

func feedRuneByRune(r *Redactor, s string) string {
	var b strings.Builder
	for _, ru := range s {
		b.WriteString(r.Feed(string(ru)))
	}
	b.WriteString(r.Flush())
	return b.String()
}

func hexOf(s string) string { return hex.EncodeToString([]byte(s)) }

// wrapEvery inserts a newline after every n runes, the pathological end of what
// fold/fmt/pr can do to a value.
func wrapEvery(s string, n int) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 && i%n == 0 {
			b.WriteByte('\n')
		}
		b.WriteRune(c)
	}
	return b.String()
}

// A. Overlap sufficiency: even the longest variant, wrapped after every single
// character, must be caught when it dribbles in one rune at a time. The overlap
// is 2*longest+16 and the worst wrapped form of the longest variant is < 2*
// longest, so this should always hold; the test pins that it does after the
// variant set grew.
func TestOverlapHoldsPathologicalWrap(t *testing.T) {
	forms := map[string]string{
		"raw/wrap1":     wrapEvery(streamSecret, 1),
		"raw/wrap3":     wrapEvery(streamSecret, 3),
		"hex/wrap1":     wrapEvery(hexOf(streamSecret), 1),
		"percent/wrap1": wrapEvery(percentEncode(streamSecret, false), 1),
	}
	for name, form := range forms {
		r := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
		got := feedRuneByRune(r, "head\n"+form+"\ntail")
		rejoined := strings.ReplaceAll(got, "\n", "")
		if strings.Contains(rejoined, streamSecret) {
			t.Errorf("%s: secret recoverable after rejoining lines: %q", name, got)
		}
		if strings.Contains(strings.ReplaceAll(rejoined, "\n", ""), hexOf(streamSecret)) {
			t.Errorf("%s: hex form survived: %q", name, got)
		}
	}
}

// B. Colour codes spliced into a value: the doc's own claim. Stripped before
// matching, so the value is caught.
func TestColourSpliceIsStripped(t *testing.T) {
	spliced := map[string]string{
		"sgr-mid":   "hunter2correct\x1b[32mhorsebatteryZ9",
		"reset-mid": "hunter2\x1b[0mcorrecthorsebatteryZ9",
		"osc-mid":   "hunter2\x1b]0;title\x07correcthorsebatteryZ9",
		"per-char":  spliceEveryChar(streamSecret, "\x1b[32m"),
	}
	for name, s := range spliced {
		r := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
		got := r.RedactText("x " + s + " y")
		if strings.Contains(got, streamSecret) {
			t.Errorf("%s: raw secret leaked despite stripping: %q", name, got)
		}
		// Fed one rune at a time, the escape splits across chunks too.
		r2 := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
		if got2 := feedRuneByRune(r2, "x "+s+" y"); strings.Contains(got2, streamSecret) {
			t.Errorf("%s (streamed): raw secret leaked: %q", name, got2)
		}
	}
}

// C. The boundary.  These splice a separator the terminal collapses (or hides)
// but ansiRE does not strip, so the value is split in the matched text and
// escapes.  All require deliberate crafting, the same class as `| rev`, and the
// threat model documents that class as out of scope.
//
// Asserted rather than printed, so it is a boundary and not a note: each case
// pins where stage 1 stops.  A separator that starts being stripped fails here,
// which is the signal to widen ansiRE deliberately and move the case up to the
// covered set rather than to discover the change by reading output.
func TestZeroWidthSplicingSurvivesStage1(t *testing.T) {
	for _, tc := range []struct{ name, sep string }{
		{"zero-width space", "\u200b"},
		{"zero-width joiner", "\u200d"},
		{"word joiner", "\u2060"},
		{"soft hyphen", "\u00ad"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
			got := r.RedactText(spliceEveryChar(streamSecret, tc.sep))

			// Whole in the output once the separator is taken back out, which is what
			// a reader of that output does for free.
			stripped := strings.ReplaceAll(got, tc.sep, "")
			if !strings.Contains(stripped, streamSecret) {
				t.Errorf("%s is now handled by stage 1: %q.\nThat is an improvement, "+
					"not a regression: move this case to the covered set and say so in "+
					"docs/redaction.md", tc.name, got)
			}
		})
	}
}

func spliceEveryChar(s, sep string) string {
	var b strings.Builder
	for i, c := range s {
		if i > 0 {
			b.WriteString(sep)
		}
		b.WriteRune(c)
	}
	return b.String()
}
