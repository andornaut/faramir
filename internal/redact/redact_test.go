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

func TestPlainValueIsReplaced(t *testing.T) {
	r := newTestRedactor()
	out := r.RedactText("password is " + secret + " ok")
	if strings.Contains(out, secret) {
		t.Fatalf("plaintext survived: %q", out)
	}
	if !strings.Contains(out, want()) {
		t.Fatalf("token missing: %q", out)
	}
}

func TestBase64VariantsAreReplaced(t *testing.T) {
	for name, encoded := range map[string]string{
		"std":          base64.StdEncoding.EncodeToString([]byte(secret)),
		"std-unpadded": strings.TrimRight(base64.StdEncoding.EncodeToString([]byte(secret)), "="),
		"url":          base64.URLEncoding.EncodeToString([]byte(secret)),
		"url-unpadded": strings.TrimRight(base64.URLEncoding.EncodeToString([]byte(secret)), "="),
	} {
		r := newTestRedactor()
		out := r.RedactText("blob: " + encoded)
		if strings.Contains(out, encoded) {
			t.Errorf("%s survived: %q", name, out)
		}
	}
}

// base64 wraps at 76 columns, which splits a value across lines.
func TestWrappedBase64IsReplaced(t *testing.T) {
	long := strings.Repeat(secret, 6)
	r := New([]Secret{{Ref: "big", Value: long}}, DefaultPolicy())
	encoded := base64.StdEncoding.EncodeToString([]byte(long))
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 76 {
		end := min(i+76, len(encoded))
		wrapped.WriteString(encoded[i:end] + "\n")
	}
	out := r.RedactText("start\n" + wrapped.String() + "end\n")
	if strings.Contains(out, encoded[:40]) {
		t.Fatalf("wrapped base64 survived: %q", out)
	}
	if !strings.Contains(out, TokenFor("big")) {
		t.Fatalf("token missing: %q", out)
	}
	if !strings.Contains(out, "start") || !strings.Contains(out, "end") {
		t.Errorf("surrounding output was destroyed: %q", out)
	}
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

// A colour code spliced into the middle must not defeat the match.
func TestANSIInsideValueIsStripped(t *testing.T) {
	r := newTestRedactor()
	half := len(secret) / 2
	out := r.RedactText(secret[:half] + "\x1b[31m" + secret[half:])
	if strings.Contains(out, secret[:half]) {
		t.Fatalf("ANSI splice defeated the matcher: %q", out)
	}
	if !strings.Contains(out, want()) {
		t.Fatalf("token missing: %q", out)
	}
}

func TestURLAndJSONEncodings(t *testing.T) {
	withSpecials := "p@ss word/with+specials=x"
	r := New([]Secret{{Ref: "k", Value: withSpecials}}, DefaultPolicy())
	out := r.RedactText("url=" + percentEncode(withSpecials, false) +
		" plus=" + percentEncode(withSpecials, true) +
		" json=" + jsonEscape(withSpecials))
	for _, enc := range []string{
		percentEncode(withSpecials, false),
		percentEncode(withSpecials, true),
	} {
		if strings.Contains(out, enc) {
			t.Errorf("encoding survived: %q in %q", enc, out)
		}
	}
}

// Longest first: if one secret contains another, the longer token must win.
func TestLongestValueWins(t *testing.T) {
	short := "abcdefgh12"
	long := short + "-and-more-here"
	r := New([]Secret{
		{Ref: "short", Value: short},
		{Ref: "long", Value: long},
	}, DefaultPolicy())
	out := r.RedactText("value: " + long)
	if !strings.Contains(out, TokenFor("long")) {
		t.Fatalf("longer secret did not win: %q", out)
	}
	if strings.Contains(out, short) {
		t.Errorf("fragment of the short secret survived: %q", out)
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

// A refused value must not be matched at all, and must be reported.
func TestRefusedValueIsSkipped(t *testing.T) {
	r := New([]Secret{{Ref: "tiny", Value: "abc"}}, DefaultPolicy())
	if r.Active() {
		t.Error("a refused value produced an active matcher")
	}
	if len(r.Skipped) != 1 || r.Skipped[0].Ref != "tiny" {
		t.Errorf("refusal not reported: %+v", r.Skipped)
	}
	if out := r.RedactText("abc"); out != "abc" {
		t.Errorf("a refused value was redacted anyway: %q", out)
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

// Multi-byte characters must survive chunk boundaries intact.
func TestUnicodeIsPreserved(t *testing.T) {
	r := newTestRedactor()
	text := "héllo wörld ← " + secret + " → done"
	out := r.RedactText(text)
	if !strings.Contains(out, "héllo wörld ←") || !strings.Contains(out, "→ done") {
		t.Errorf("unicode mangled: %q", out)
	}
	if strings.Contains(out, secret) {
		t.Errorf("plaintext survived: %q", out)
	}
}

func TestEmptyRedactorPassesTextThrough(t *testing.T) {
	r := New(nil, DefaultPolicy())
	const text = "nothing to redact here"
	if out := r.RedactText(text); out != text {
		t.Errorf("got %q, want %q", out, text)
	}
}
