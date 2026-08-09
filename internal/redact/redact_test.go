package redact

import (
	"encoding/base64"
	"fmt"
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
	// A quote and a backslash, so the JSON and shell forms below are something
	// other than the value spelled again.
	const specials = `p@ss "wo\rd" with+specials=x`
	// An apostrophe is what makes the shell-quoted forms unrecognisable: the
	// plain value is not a substring of either of them.
	const apostrophe = "it's-a-long-secret-value"
	const dollars = "pa$$word-that-is-long"
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
		// Each of these asserts the token as well as the disappearance: a redactor
		// that dropped the match rather than substituting for it would leave no
		// value behind and no sign that anything had been there.
		{name: "base64 std",
			text: "blob: " + base64.StdEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.StdEncoding.EncodeToString([]byte(secret))},
			want: []string{want()}},
		{name: "base64 std unpadded",
			text: "blob: " + unpadded(base64.StdEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.StdEncoding.EncodeToString([]byte(secret)))},
			want: []string{want()}},
		{name: "base64 url",
			text: "blob: " + base64.URLEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.URLEncoding.EncodeToString([]byte(secret))},
			want: []string{want()}},
		{name: "base64 url unpadded",
			text: "blob: " + unpadded(base64.URLEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.URLEncoding.EncodeToString([]byte(secret)))},
			want: []string{want()}},
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
			gone: []string{
				percentEncode(specials, false), percentEncode(specials, true),
				jsonEscape(specials),
			},
			want: []string{TokenFor("k")}},
		// A "set -x" trace prints the value the way the shell quotes it, and for a
		// value holding an apostrophe that form carries the plain one nowhere in
		// it: matching the value alone would leave the whole trace line intact.
		// The quoted forms are spelled out rather than built with the package's
		// own helpers, so this compares against what a shell actually prints.
		{name: "shell single-quoted, as set -x prints it",
			secrets: []Secret{{Ref: "k", Value: apostrophe}},
			text:    `+ curl --user 'it'"'"'s-a-long-secret-value' https://host` + "\n",
			gone:    []string{`'it'"'"'s-a-long-secret-value'`},
			want:    []string{TokenFor("k"), "https://host"}},
		{name: "shell double-quoted, with the escapes the shell adds",
			secrets: []Secret{{Ref: "k", Value: dollars}},
			text:    `+ curl --user "pa\$\$word-that-is-long" https://host` + "\n",
			gone:    []string{`pa\$\$word-that-is-long`},
			want:    []string{TokenFor("k"), "https://host"}},
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
	for _, tc := range []struct{ name, value string }{
		{"short", "abc"},
		{"few unique characters", "aaaaaaaaaaaa"},
		{"low entropy", "ababababababab"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if reason := policy.Check(tc.value); reason == "" {
				t.Errorf("%q was accepted", tc.value)
			}
		})
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
	for _, tc := range []struct{ name, in, want string }{
		{"a colour span", "\x1b[31mred\x1b[0m", "red"},
		{"an OSC title, terminated by BEL", "a\x1b]0;title\x07b", "ab"},
		{"a PTY's CRLF becomes a newline", "line\r\nnext", "line\nnext"},
		{"a reset with no parameter", "\x1b[1;32mbold green\x1b[m done", "bold green done"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := StripANSI(tc.in); got != tc.want {
				t.Errorf("StripANSI(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestEmptyRedactorPassesTextThrough(t *testing.T) {
	r := New(nil, DefaultPolicy())
	const text = "nothing to redact here"
	if out := r.RedactText(text); out != text {
		t.Errorf("got %q, want %q", out, text)
	}
}

// The broker builds a redactor per request and two more per exec, each one
// compiling roughly ten patterns per secret, and then runs every entry over
// every chunk of a child's output.  Both costs scale with the size of the
// store, which is the number nobody notices growing.
//
//	go test ./internal/redact/ -bench Redactor -benchmem
func manySecrets(n int) []Secret {
	out := make([]Secret, n)
	for i := range out {
		out[i] = Secret{
			Ref:   fmt.Sprintf("svc%03d/token", i),
			Value: fmt.Sprintf("s3cret-%03d-%s", i, strings.Repeat("xKq7", 6)),
		}
	}
	return out
}

func BenchmarkRedactorNew(b *testing.B) {
	for _, n := range []int{10, 50, 200} {
		b.Run(fmt.Sprintf("secrets=%d", n), func(b *testing.B) {
			secrets := manySecrets(n)
			b.ReportAllocs()
			for b.Loop() {
				New(secrets, DefaultPolicy())
			}
		})
	}
}

func BenchmarkRedactorFeed(b *testing.B) {
	for _, n := range []int{10, 50, 200} {
		b.Run(fmt.Sprintf("secrets=%d", n), func(b *testing.B) {
			secrets := manySecrets(n)
			// A chunk the size of the executor's own read buffer, holding one
			// value so the replacing path is measured and not only the scan.
			chunk := strings.Repeat("ordinary build output line\n", 2400) +
				secrets[n/2].Value + "\n"
			b.SetBytes(int64(len(chunk)))
			b.ReportAllocs()
			for b.Loop() {
				r := New(secrets, DefaultPolicy())
				r.Feed(chunk)
				r.Flush()
			}
		})
	}
}
