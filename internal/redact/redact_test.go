package redact

import (
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"testing"
)

const secret = "hunter2-correct-horse"

// wrapped is the secret as a formatter that broke the line would leave it, and
// digity carries a 9 and a character that percent-encodes, so the encoded
// rendering differs from the value and the digit's own class is exercised.
var (
	wrapped = secret[:11] + "\n" + secret[11:]
	digity  = "secret9 value here"
)

func newTestRedactor() *Redactor {
	return New([]Secret{{Ref: "home/router/admin", Value: secret}}, DefaultPolicy())
}

// routerToken is the token the default redactor replaces `secret` with.
func routerToken() string { return TokenFor("home/router/admin") }

// One redactor, one text, and three questions: is the value gone, is its token
// there, did the surrounding output survive. Each encoding is a separate way
// for the same secret to escape.
func TestRedactTextCoversEveryVariantSpelling(t *testing.T) {
	// A quote and a backslash, so the JSON and shell forms differ from the
	// value.
	const specials = `p@ss "wo\rd" with+specials=x`
	// An apostrophe, so the plain value is not a substring of the shell-quoted
	// forms.
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
			gone: []string{secret}, want: []string{routerToken()}},
		// The token as well as the disappearance: a redactor that dropped the
		// match would leave no sign anything had been there.
		{name: "base64 std",
			text: "blob: " + base64.StdEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.StdEncoding.EncodeToString([]byte(secret))},
			want: []string{routerToken()}},
		{name: "base64 std unpadded",
			text: "blob: " + unpadded(base64.StdEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.StdEncoding.EncodeToString([]byte(secret)))},
			want: []string{routerToken()}},
		{name: "base64 url",
			text: "blob: " + base64.URLEncoding.EncodeToString([]byte(secret)),
			gone: []string{base64.URLEncoding.EncodeToString([]byte(secret))},
			want: []string{routerToken()}},
		{name: "base64 url unpadded",
			text: "blob: " + unpadded(base64.URLEncoding.EncodeToString([]byte(secret))),
			gone: []string{unpadded(base64.URLEncoding.EncodeToString([]byte(secret)))},
			want: []string{routerToken()}},
		// base64 wraps at 76 columns, which splits a value across lines.
		{name: "base64 wrapped at 76 columns",
			secrets: []Secret{{Ref: "big", Value: long}},
			text:    "start\n" + wrap76(base64.StdEncoding.EncodeToString([]byte(long))) + "end\n",
			gone:    []string{base64.StdEncoding.EncodeToString([]byte(long))[:40]},
			want:    []string{TokenFor("big"), "start", "end"}},
		// A colour code spliced into the middle.
		{name: "ANSI spliced into the middle",
			text: secret[:len(secret)/2] + "\x1b[31m" + secret[len(secret)/2:],
			gone: []string{secret[:len(secret)/2]}, want: []string{routerToken()}},
		{name: "percent and JSON encodings",
			secrets: []Secret{{Ref: "k", Value: specials}},
			text: "url=" + percentEncode(specials, safeQuote, false, false) +
				" plus=" + percentEncode(specials, safeQuote, true, false) +
				" json=" + jsonEscape(specials),
			gone: []string{
				percentEncode(specials, safeQuote, false, false), percentEncode(specials, safeQuote, true, false),
				jsonEscape(specials),
			},
			want: []string{TokenFor("k")}},
		// A "set -x" trace prints the shell-quoted form, which for a value
		// holding an apostrophe carries the plain one nowhere. Spelled out
		// rather than built with the package's helpers, so this compares
		// against what a shell prints.
		{name: "shell single-quoted, as set -x prints it",
			secrets: []Secret{{Ref: "k", Value: apostrophe}},
			text:    `+ curl --user 'it'"'"'s-a-long-secret-value' https://host` + "\n",
			gone:    []string{`'it'"'"'s-a-long-secret-value'`},
			want:    []string{TokenFor("k"), "https://host"}},
		// The other escape for the same character: bash prints one, Python's
		// shlex.quote the other, and docs/redaction.md claims both.
		{name: `shell single-quoted, the '\'' escape`,
			secrets: []Secret{{Ref: "k", Value: apostrophe}},
			text:    `+ curl --user 'it'\''s-a-long-secret-value' https://host` + "\n",
			gone:    []string{`'it'\''s-a-long-secret-value'`},
			want:    []string{TokenFor("k"), "https://host"}},
		{name: "shell double-quoted, with the escapes the shell adds",
			secrets: []Secret{{Ref: "k", Value: dollars}},
			text:    `+ curl --user "pa\$\$word-that-is-long" https://host` + "\n",
			gone:    []string{`pa\$\$word-that-is-long`},
			want:    []string{TokenFor("k"), "https://host"}},
		// Longest first, so a secret containing another wins.
		{name: "one secret inside another",
			secrets: []Secret{
				{Ref: "short", Value: "abcdefgh12"},
				{Ref: "long", Value: "abcdefgh12-and-more-here"},
			},
			text: "value: abcdefgh12-and-more-here",
			gone: []string{"abcdefgh12"}, want: []string{TokenFor("long")}},
		// Multi-byte characters across a chunk boundary.
		{name: "unicode around the value",
			text: "héllo wörld ← " + secret + " → done",
			gone: []string{secret}, want: []string{"héllo wörld ←", "→ done"}},
		// Two wrapped renderings with nothing between them. The second starts
		// exactly where the first ended, which is adjacent rather than
		// overlapping: read as overlapping it is skipped as already covered, and
		// the tail is then written out as it came in.
		{name: "the same value wrapped and repeated back to back",
			text: "before\n" + wrapped + wrapped + "after\n",
			gone: []string{wrapped}, want: []string{routerToken(), "before", "after"}},
		// And with a gap, which is the ordinary case the one above is bounded by.
		{name: "the same value wrapped twice with text between",
			text: "a " + wrapped + " middle " + wrapped + " b",
			gone: []string{wrapped}, want: []string{routerToken(), "middle"}},
		// Percent-encoding, where the digits are one of the classes left as they
		// are. A digit encoded when it should be literal renders a variant that
		// matches nothing, so the encoded value goes out whole.
		{name: "percent-encoded with a digit in the value",
			secrets: []Secret{{Ref: "k", Value: digity}},
			text:    "url: https://host/?q=" + url.QueryEscape(digity),
			gone:    []string{url.QueryEscape(digity)},
			want:    []string{TokenFor("k"), "https://host"}},
		{name: "path-encoded with a digit in the value",
			secrets: []Secret{{Ref: "k", Value: digity}},
			text:    "url: https://host/" + url.PathEscape(digity),
			gone:    []string{url.PathEscape(digity)},
			want:    []string{TokenFor("k"), "https://host"}},
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
	if !strings.Contains(got, routerToken()) {
		t.Fatalf("token missing: %q", got)
	}
}

// Length is the whole of the test. A short value matches inside ordinary
// words, so redacting it would blank unrelated output at random; that is about
// what this program does with a value rather than about the value.
func TestATooShortValueIsRefused(t *testing.T) {
	policy := DefaultPolicy()
	for _, value := range []string{"", "abc", "1234567"} {
		if reason := policy.Check(value); reason == "" {
			t.Errorf("%q was accepted", value)
		}
	}
	if reason := policy.Check(secret); reason != "" {
		t.Errorf("a good value was refused: %s", reason)
	}
}

// How strong a credential is belongs to whoever chose it. A distinct-character
// or Shannon-entropy floor would refuse to carry values it graded as weak while
// not being the strength check it reads as: "password" clears both.
func TestAWeakButLongValueIsCarried(t *testing.T) {
	policy := DefaultPolicy()
	for _, value := range []string{"password", "aaaaaaaaaaaa", "ababababababab"} {
		if reason := policy.Check(value); reason != "" {
			t.Errorf("%q was refused as %q; strength is the operator's call", value, reason)
		}
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
			if got := stripANSI(tc.in); got != tc.want {
				t.Errorf("stripANSI(%q) = %q, want %q", tc.in, got, tc.want)
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

// The broker builds a redactor per request and two more per exec, each compiling
// roughly ten patterns per secret, then runs every entry over every chunk. Both
// costs scale with the size of the value set.
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
			// The size of the executor's read buffer, holding one value so the
			// replacing path is measured too.
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

// A value carrying bytes stage 1 rewrites is still a value the output has to
// come back without. Stage 1 normalises the text before any matching, so the
// value as it appears in the store is not the value as it appears in the
// output, and the matcher carries both.
func TestAValueStage1RewritesIsStillRedacted(t *testing.T) {
	for _, c := range []struct{ name, value string }{
		{"a CRLF, as a file written on Windows holds", "line-one\r\nline-two-secret"},
		{"a C0 control", "abc\x01defghij"},
		{"a DEL", "abcdef\x7fghijkl"},
		{"an escape sequence", "abcd\x1b[0mefghij"},
		{"a bare CR, which stage 1 keeps", "abcdef\rghijkl"},
	} {
		r := New([]Secret{{Ref: "a/b", Value: c.value}}, DefaultPolicy())
		got := r.RedactText("before " + c.value + " after")
		if want := "before " + TokenFor("a/b") + " after"; got != want {
			t.Errorf("%s: got %q, want %q", c.name, got, want)
		}
	}
}

// And the bound on that: a value that is mostly control characters strips to
// something too short to search output for, and adding it would blank
// unrelated text. The policy decides, as it does for the value itself.
func TestAValueThatStripsUnderTheFloorIsNotAdded(t *testing.T) {
	r := New([]Secret{{Ref: "a/b", Value: strings.Repeat("\x01", 10) + "ab"}}, DefaultPolicy())
	const text = "a table of abbreviations"
	if got := r.RedactText(text); got != text {
		t.Errorf("a value that strips to %q ate the output: %q", "ab", got)
	}
}

// One pass over the output whatever the number of values, so the scan does not
// cost the number of refs times the size of what a command printed.
func TestEveryValueIsOneAutomaton(t *testing.T) {
	secrets := []Secret{
		{Ref: "a/one", Value: "hunter2-correct-horse"},
		{Ref: "b/two", Value: "tok_live_0PENSESAME_9911"},
	}
	r := New(secrets, DefaultPolicy())
	if r.matcher == nil {
		t.Fatal("no matcher was built")
	}
	for _, s := range secrets {
		if r.tokenOf[s.Value] != TokenFor(s.Ref) {
			t.Errorf("%s does not map to its own token: %q", s.Ref, r.tokenOf[s.Value])
		}
	}
	out := r.RedactText(secrets[0].Value + " and " + secrets[1].Value)
	if want := TokenFor("a/one") + " and " + TokenFor("b/two"); out != want {
		t.Errorf("out = %q, want %q", out, want)
	}
}

// A value at or over the kernel's cap on one environment variable is one
// faramir could never inject, and holding it is not free: the automaton costs
// about 19 KB of memory per byte, so a 200 KB value takes the broker to several
// gigabytes and the OOM killer takes it from there, at which point nothing on
// the host is redacted.
func TestAValueTooLargeToInjectIsRefused(t *testing.T) {
	policy := DefaultPolicy()
	for _, tc := range []struct {
		name    string
		size    int
		refused bool
	}{
		{"an ordinary token", 40, false},
		{"a private key", 3000, false},
		{"a kubeconfig", 20000, false},
		{"just under the cap", MaxValueBytes - 1, false},
		{"at the cap", MaxValueBytes, true},
		{"far over it", MaxValueBytes * 2, true},
	} {
		why := policy.Check(strings.Repeat("a", tc.size))
		if refused := why != ""; refused != tc.refused {
			t.Errorf("%s (%d bytes): refused = %v (%q), want %v",
				tc.name, tc.size, refused, why, tc.refused)
		}
	}
	// The reason says which limit and why it matters, or an operator is told a
	// size and no reason to care about it.
	why := policy.Check(strings.Repeat("a", MaxValueBytes))
	for _, want := range []string{"environment variable", "injected"} {
		if !strings.Contains(why, want) {
			t.Errorf("the reason does not mention %q: %s", want, why)
		}
	}
}
