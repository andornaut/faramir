package redact

import (
	"encoding/hex"
	"strings"
	"testing"
)

// Aimed at the streaming machine and at stage-1 stripping rather than at the
// encoding-variant set: the overlap buffer against a pathological line wrap fed
// one rune at a time, a colour code spliced into a value, and the separator that
// stage 1 does not strip, which is where the covered set ends.

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

// Overlap sufficiency: even the longest variant, wrapped after every single
// character, must be caught when it dribbles in one rune at a time. The overlap
// is 2*longest+16 and the worst wrapped form of the longest variant is under
// 2*longest, so this pins that the variant set has not outgrown the window.
func TestOverlapHoldsPathologicalWrap(t *testing.T) {
	for _, tc := range []struct{ name, form string }{
		{"raw/wrap1", wrapEvery(streamSecret, 1)},
		{"raw/wrap3", wrapEvery(streamSecret, 3)},
		{"hex/wrap1", wrapEvery(hexOf(streamSecret), 1)},
		{"percent/wrap1", wrapEvery(percentEncode(streamSecret, false), 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
			got := feedRuneByRune(r, "head\n"+tc.form+"\ntail")
			rejoined := strings.ReplaceAll(got, "\n", "")
			if strings.Contains(rejoined, streamSecret) {
				t.Errorf("secret recoverable after rejoining lines: %q", got)
			}
			if strings.Contains(rejoined, hexOf(streamSecret)) {
				t.Errorf("hex form survived: %q", got)
			}
		})
	}
}

// Colour codes spliced into a value are stripped before matching, so the value
// is caught.
func TestColourSpliceIsStripped(t *testing.T) {
	for _, tc := range []struct{ name, spliced string }{
		{"sgr-mid", "hunter2correct\x1b[32mhorsebatteryZ9"},
		{"reset-mid", "hunter2\x1b[0mcorrecthorsebatteryZ9"},
		{"osc-mid", "hunter2\x1b]0;title\x07correcthorsebatteryZ9"},
		{"per-char", spliceEveryChar(streamSecret, "\x1b[32m")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
			if got := r.RedactText("x " + tc.spliced + " y"); strings.Contains(got, streamSecret) {
				t.Errorf("raw secret leaked despite stripping: %q", got)
			}
			// Fed one rune at a time, the escape splits across chunks too.
			streamed := New([]Secret{{Ref: "svc/token", Value: streamSecret}}, DefaultPolicy())
			if got := feedRuneByRune(streamed, "x "+tc.spliced+" y"); strings.Contains(got, streamSecret) {
				t.Errorf("streamed: raw secret leaked: %q", got)
			}
		})
	}
}

// The boundary.  These splice a separator the terminal collapses (or hides) but
// ansiRE does not strip, so the value is split in the matched text and escapes.
// All require deliberate crafting, the same class as `| rev`, which the threat
// model documents as out of scope.
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

			// Whole in the output once the separator is taken back out, which any
			// reader of that output does without trying.
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
