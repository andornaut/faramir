package redact

import (
	"strings"
	"testing"
)

// The accented tail of the canary below, as an encoder that escapes non-ASCII
// writes it. Written with doubled backslashes so what the test compares is the
// six-character sequence a reader sees in output, not the character itself.
const escapedTail = "\\u00fc\\u00f1\\u00ee\\u00e7\\u00f8d\\u00e9"

// A value carrying a non-ASCII character is rendered by json.dumps and by
// json_encode with that character escaped, and by Go's encoder with it left as
// UTF-8. All three spellings have to be caught: the escaped one changes only the
// accented tail, so matching the raw spelling alone puts the rest of the value,
// sentinel and all, out in the clear.
func TestAValueIsRedactedWhicheverJSONEncoderPrintedIt(t *testing.T) {
	const (
		ascii = "CANARY-unicode-8f3a91c2-"
		tail  = "üñîçødé"
		value = ascii + tail
		ref   = "agenttest/unicode"
	)

	for _, tc := range []struct {
		name string
		text string
	}{
		{"go, non-ASCII left as UTF-8", `{"k":"` + value + `"}`},
		{"python json.dumps, default arguments", `{"k": "` + ascii + escapedTail + `"}`},
		{"php json_encode, default arguments", `{"k":"` + ascii + escapedTail + `"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			out := New([]Secret{{Ref: ref, Value: value}}, EligibilityPolicy{MinLength: 8}).
				RedactText(tc.text)
			if strings.Contains(out, ascii) {
				t.Errorf("the ASCII half of the value survived: %q", out)
			}
			if !strings.Contains(out, TokenFor(ref)) {
				t.Errorf("no token, so nothing matched and nothing would be counted: %q", out)
			}
		})
	}
}

// An all-ASCII value has nothing for the escaping to change, so both spellings
// are one string and the rendering set does not grow.
func TestAnASCIIValueGainsNoJSONVariant(t *testing.T) {
	const value = "CANARY-plain-4d9e7b10"
	if got, want := jsonEscapeASCII(value), jsonEscape(value); got != want {
		t.Errorf("jsonEscapeASCII(%q) = %q, want the unescaped spelling %q", value, got, want)
	}
}

// An astral rune has no single \u spelling, so every JSON encoder writes it as a
// surrogate pair.
func TestAnAstralRuneBecomesASurrogatePair(t *testing.T) {
	got := jsonEscapeASCII("a\U0001F511b")
	want := "a" + "\\ud83d\\udd11" + "b"
	if got != want {
		t.Errorf("jsonEscapeASCII = %q, want %q", got, want)
	}
}
