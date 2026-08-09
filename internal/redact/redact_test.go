package redact

import (
	"encoding/base64"
	"strings"
	"testing"
)

const secret = "hunter2-correct-horse"

func newTestRedactor() *Redactor {
	return New([]Secret{{Ref: "home/router/admin", Value: secret}}, DefaultPolicy())
}

func want() string { return TokenFor("home/router/admin") }

// One redactor, one text, and the three questions every one of these asks: is
// the value gone, is its token there, and did the surrounding output survive.
//
// The encodings are the point of the table.  A value reaches a transcript
// through whatever the command printed it as, so each encoding is a separate
// way for the same secret to escape, and they are worth reading as one list.
func TestRedactText(t *testing.T) {
	const specials = "p@ss word/with+specials=x"
	long := strings.Repeat(secret, 6)

	for _, tc := range []struct {
		name    string
		secrets []Secret // nil is the default one-secret redactor
		text    string
		gone    []string // must not appear in the output
		want    []string // must appear
	}{
		{name: "plain",
			text: "password is " + secret + " ok",
			gone: []string{secret}, want: []string{want()}},
		{name: "base64 std",
			text: "blob: " + base64.StdEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.StdEncoding.EncodeToString([]byte(secret))}},
		{name: "base64 std unpadded",
			text: "blob: " + unpadded(base64.StdEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.StdEncoding.EncodeToString([]byte(secret)))}},
		{name: "base64 url",
			text: "blob: " + base64.URLEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.URLEncoding.EncodeToString([]byte(secret))}},
		{name: "base64 url unpadded",
			text: "blob: " + unpadded(base64.URLEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.URLEncoding.EncodeToString([]byte(secret)))}},
		// base64 wraps at 76 columns, which splits a value across lines.
		{name: "base64 wrapped at 76 columns",
			secrets: []Secret{{Ref: "big", Value: long}},
			text:    "start\n" + wrap76(base64.StdEncoding.EncodeToString([]byte(long))) + "end\n",
			gone:    []string{base64.StdEncoding.EncodeToString([]byte(long))[:40]},
			want:    []string{TokenFor("big"), "start", "end"}},
		// A colour code spliced into the middle must not defeat the match.
		{name: "ANSI spliced into the middle",
			text: secret[:len(secret)/2] + "\x1b[31m" + secret[len(secret)/2:],
			gone: []string{secret[:len(secret)/2]}, want: []string{want()}},
		{name: "percent and JSON encodings",
			secrets: []Secret{{Ref: "k", Value: specials}},
			text: "url=" + percentEncode(specials, false) +
				" plus=" + percentEncode(specials, true) +
				" json=" + jsonEscape(specials),
			gone: []string{percentEncode(specials, false), percentEncode(specials, true)}},
		// Longest first: if one secret contains another, the longer token wins.
		{name: "one secret inside another",
			secrets: []Secret{
				{Ref: "short", Value: "abcdefgh12"},
				{Ref: "long", Value: "abcdefgh12-and-more-here"},
			},
			text: "value: abcdefgh12-and-more-here",
			gone: []string{"abcdefgh12"}, want: []string{TokenFor("long")}},
		// Multi-byte characters must survive chunk boundaries intact.
		{name: "unicode around the value",
			text: "héllo wörld ← " + secret + " → done",
			gone: []string{secret}, want: []string{"héllo wörld ←", "→ done"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			secrets := tc.secrets
			if secrets == nil {
				secrets = []Secret{{Ref: "home/router/admin", Value: secret}}
			}
			out := New(secrets, DefaultPolicy()).RedactText(tc.text)
			for _, gone := range tc.gone {
				if strings.Contains(out, gone) {
					t.Errorf("survived: %q in %q", gone, out)
				}
			}
			for _, want := range tc.want {
				if !strings.Contains(out, want) {
					t.Errorf("missing %q in %q", want, out)
				}
			}
		})
	}
}

func unpadded(s string) string { return strings.TrimRight(s, "=") }

func wrap76(s string) string {
	var out strings.Builder
	for i := 0; i < len(s); i += 76 {
		out.WriteString(s[i:min(i+76, len(s))] + "\n")
	}
	return out.String()
}

// A value split across two Feed calls must still be caught.
func TestValueSplitAcrossChunks(t *testing.T) {
	r := newTestRedactor()
	half := len(secret) / 2
	var out strings.Builder
	out.WriteString(r.Feed("before " + secret[:half]))
	out.WriteString(r.Feed(secret[half:] + " after"))
	out.WriteString(r.Flush())
	got := out.String()
	if strings.Contains(got, secret) {
		t.Fatalf("split value survived: %q", got)
	}
	if !strings.Contains(got, want()) {
		t.Fatalf("token missing: %q", got)
	}
}

func TestEligibilityRefusals(t *testing.T) {
	policy := DefaultPolicy()
	cases := map[string]string{
		"short":       "abc",
		"few-unique":  "aaaaaaaaaaaa",
		"low-entropy": "ababababababab",
	}
	for name, value := range cases {
		if reason := policy.Check(value); reason == "" {
			t.Errorf("%s (%q) was accepted", name, value)
		}
	}
	if reason := policy.Check(secret); reason != "" {
		t.Errorf("a good value was refused: %s", reason)
	}
}

func TestSummaryCountsNotValues(t *testing.T) {
	r := newTestRedactor()
	r.RedactText(secret + " " + secret + " " + secret)
	summary := r.Summary()
	if len(summary) != 1 {
		t.Fatalf("summary = %+v", summary)
	}
	if summary[0].Count != 3 {
		t.Errorf("count = %d, want 3", summary[0].Count)
	}
	if strings.Contains(summary[0].Token, secret) {
		t.Error("the summary contains the value")
	}
}

func TestStripANSI(t *testing.T) {
	cases := map[string]string{
		"\x1b[31mred\x1b[0m":              "red",
		"a\x1b]0;title\x07b":              "ab",
		"line\r\nnext":                    "line\nnext",
		"\x1b[1;32mbold green\x1b[m done": "bold green done",
	}
	for in, want := range cases {
		if got := StripANSI(in); got != want {
			t.Errorf("StripANSI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestEmptyRedactorPassesTextThrough(t *testing.T) {
	r := New(nil, DefaultPolicy())
	const text = "nothing to redact here"
	if out := r.RedactText(text); out != text {
		t.Errorf("got %q, want %q", out, text)
	}
}
