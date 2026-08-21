package redact

import (
	"strings"
	"testing"
)

// A percent-encoder is named by the characters it leaves alone, and the three
// in wide use disagree about "!*'()" and the reserved delimiters. Covering only
// the strictest of them leaves a value that crossed a URL built by JavaScript
// in the clear, which is the ordinary way one reaches output by accident.
func TestPercentEncodedSpellingsAreRedacted(t *testing.T) {
	const value = `r0uter!pass&word<tricky>/a b`
	for _, tc := range []struct {
		name string
		text string
	}{
		{"urllib quote, safe=\"\"", "r0uter%21pass%26word%3Ctricky%3E%2Fa%20b"},
		{"encodeURIComponent", "r0uter!pass%26word%3Ctricky%3E%2Fa%20b"},
		{"encodeURI", "r0uter!pass&word%3Ctricky%3E/a%20b"},
		{"lower-case hex digits", "r0uter%21pass%26word%3ctricky%3e%2fa%20b"},
		{"form encoding, space as plus", "r0uter%21pass%26word%3Ctricky%3E%2Fa+b"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "router/admin", Value: value}}, DefaultPolicy())
			got := r.RedactText("GET /x?p=" + tc.text + " HTTP/1.1")
			if strings.Contains(got, tc.text) {
				t.Errorf("the %s spelling reached the output verbatim:\n%s", tc.name, got)
			}
			if !strings.Contains(got, TokenFor("router/admin")) {
				t.Errorf("nothing was redacted, so the spelling was not recognised:\n%s", got)
			}
		})
	}
}

// The sets differ only over characters a value may not hold. One that holds
// none of them must not pay for six renderings of itself.
func TestPercentVariantsCollapseWhenTheSetsAgree(t *testing.T) {
	if got := percentVariants("plain-value.123"); len(got) != 1 {
		t.Errorf("a value with no reserved characters produced %d renderings, want 1: %v",
			len(got), got)
	}
}
