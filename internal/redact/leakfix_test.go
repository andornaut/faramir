package redact

import (
	"strings"
	"testing"
)

// The value itself is split across two Feed calls, and its first character was
// eaten by a dangling CSI in the first chunk. The reinserted byte has to survive
// the chunk boundary, or the value goes out missing only its first character.
func TestValueSplitAfterDanglingCSIDoesNotLeak(t *testing.T) {
	const value = "hunter2-correct-horse-battery-staple"
	r := New([]Secret{{Ref: "db/password", Value: value}}, EligibilityPolicy{MinLength: 8})
	out := r.Feed("\x1b["+value[:10]) + r.Feed(value[10:]+"\n") + r.Flush()
	if strings.Contains(out, value[1:]) {
		t.Fatalf("the value leaked across the join: %q", out)
	}
	if !strings.Contains(out, TokenFor("db/password")) {
		t.Fatalf("no token, so the value was not caught: %q", out)
	}
}

// Two secrets that share a run of characters: the second's rendering begins
// inside the first's. Replacing only the first must not leave the tail of the
// second in the clear.
func TestPartiallyOverlappingSecretsBothRedacted(t *testing.T) {
	a := "ABCDEFGH-alpha"
	b := "alphaZYXWVUTS"
	r := New([]Secret{{Ref: "svc/a", Value: a}, {Ref: "svc/b", Value: b}}, EligibilityPolicy{MinLength: 8})
	out := r.RedactText("x " + a + b[len("alpha"):] + " y")
	for _, leak := range []string{a, b, "ZYXWVUTS"} {
		if strings.Contains(out, leak) {
			t.Fatalf("secret material %q survived: %q", leak, out)
		}
	}
	if !strings.Contains(out, TokenFor("svc/a")) || !strings.Contains(out, TokenFor("svc/b")) {
		t.Fatalf("both tokens should appear: %q", out)
	}
}

// A CRLF whose colour code sits between the CR and the LF, with a chunk boundary
// inside the escape. Streaming must normalise it exactly as the one-shot does,
// or a multi-line secret printed this way matches neither view.
func TestCRLFAcrossEscapeAndChunkBoundary(t *testing.T) {
	whole := "abc\r\x1b[31m\ndef"
	oneShot := New(nil, DefaultPolicy()).RedactText(whole)
	r := New(nil, DefaultPolicy())
	streamed := r.Feed("abc\r\x1b[3") + r.Feed("1m\ndef") + r.Flush()
	if streamed != oneShot {
		t.Fatalf("streamed %q != one-shot %q", streamed, oneShot)
	}
}

// A rendering wrapped one character per line with a blank line between every
// character (two newlines per character) fed one rune at a time. The overlap
// window is counted in non-newline runes, so it holds the whole rendering
// however many blank lines pad it.
func TestBlankLineWrapIsHeldAndCaught(t *testing.T) {
	const secret = "hunter2correcthorsebatteryZ9"
	for _, form := range []struct {
		name  string
		value string
	}{
		{"raw", secret},
		{"hex", hexOf(secret)},
	} {
		t.Run(form.name, func(t *testing.T) {
			r := New([]Secret{{Ref: "svc/token", Value: secret}}, DefaultPolicy())
			var wrapped strings.Builder
			for i, c := range form.value {
				if i > 0 {
					wrapped.WriteString("\n\n") // a blank line between every character
				}
				wrapped.WriteRune(c)
			}
			got := feedRuneByRune(r, "head\n"+wrapped.String()+"\ntail")
			rejoined := strings.ReplaceAll(got, "\n", "")
			if strings.Contains(rejoined, secret) || strings.Contains(rejoined, hexOf(secret)) {
				t.Fatalf("secret recoverable after rejoining lines: %q", got)
			}
		})
	}
}

// Chunking-invariance: feeding the same bytes one rune at a time must produce the
// same output as redacting the whole string at once, across escapes, CRLF and
// overlapping secrets.
func TestChunkingInvariance(t *testing.T) {
	secrets := []Secret{
		{Ref: "svc/a", Value: "ABCDEFGH-alpha"},
		{Ref: "svc/b", Value: "alphaZYXWVUTS"},
		{Ref: "db/password", Value: "hunter2-correct-horse"},
	}
	for _, text := range []string{
		"x ABCDEFGH-alphaZYXWVUTS y",
		"abc\r\x1b[31m\ndef",
		"\x1b[hunter2-correct-horse\n",
		"line1\r\nhunter2-correct-horse\r\nline3",
		"prefix \x1b[32mhunter2-correct-horse\x1b[0m suffix",
	} {
		whole := New(secrets, EligibilityPolicy{MinLength: 8}).RedactText(text)
		streamed := feedRuneByRune(New(secrets, EligibilityPolicy{MinLength: 8}), text)
		if whole != streamed {
			t.Fatalf("text %q: streamed %q != whole %q", text, streamed, whole)
		}
	}
}

// A secret containing multibyte runes must be redacted no matter which byte
// boundary a Feed split lands on, including the middle of a rune. Streaming
// output must equal RedactText of the whole (chunking-invariance).
func TestMultibyteRuneSplitAcrossFeedIsRedacted(t *testing.T) {
	secret := "café-señor-naïve-passwörd" // several 2-byte runes
	values := NewValues([]Secret{{Ref: "m", Value: secret}}, DefaultPolicy())
	line := "before " + secret + " after"
	whole := values.Redactor().RedactText(line)
	if !strings.Contains(whole, TokenFor("m")) {
		t.Fatalf("whole did not redact: %q", whole)
	}
	b := []byte(line)
	for cut := 0; cut <= len(b); cut++ {
		rr := values.Redactor()
		got := rr.Feed(string(b[:cut])) + rr.Feed(string(b[cut:])) + rr.Flush()
		if got != whole {
			t.Errorf("split at byte %d: got %q, want %q", cut, got, whole)
		}
	}
}
