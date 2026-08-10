package redact

import (
	"encoding/base32"
	"encoding/hex"
	"fmt"
	"html"
	"strings"
	"testing"
)

// This file is an adversarial probe, not a shipped test. It throws a battery of
// output encodings at the redactor and reports which ones let the secret
// through. Each case is tagged with the real tool that produces that encoding
// and whether it is plausibly ACCIDENTAL (ordinary tool output -> a claimed-
// Prevented "accidental disclosure") or ADVERSARIAL (deliberate transform ->
// documented Not-prevented). Run: go test ./internal/redact -run TestAdversarialBattery -v

func redactorFor(secret, ref string) *Redactor {
	return New([]Secret{{Ref: ref, Value: secret}}, DefaultPolicy())
}

// leaks reports whether the raw secret survives redaction of `output`.
func leaks(secret, output string) (bool, string) {
	r := redactorFor(secret, "svc/token")
	got := r.RedactText(output)
	return strings.Contains(got, secret), got
}

// contains reports whether an arbitrary needle (a transformed form) survives.
func survives(secret, needle, output string) (bool, string) {
	r := redactorFor(secret, "svc/token")
	got := r.RedactText(output)
	return strings.Contains(got, needle), got
}

func TestAdversarialBattery(t *testing.T) {
	// Two secrets: one plainSecret alphanumeric (exercises hex/case), one with the
	// URL/shell/HTML metacharacters real credentials actually contain.
	plainSecret := "hunter2correcthorsebatteryZ9" // >= min_length, alnum
	richSecret := "p@ss/w0rd+tok=v&x<y>z"         // has / & < > + = @ (URL, HTML, JSON, shell)

	type probe struct {
		name   string
		secret string
		kind   string // ACCIDENTAL or ADVERSARIAL
		tool   string
		encode func(s string) string
	}

	lowerHex := func(s string) string { return hex.EncodeToString([]byte(s)) }
	upperHex := func(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

	probes := []probe{
		// ---- controls: things the redactor claims to cover ----
		{"raw", plainSecret, "COVERED", "anything", func(s string) string { return s }},
		{"raw-richSecret", richSecret, "COVERED", "anything", func(s string) string { return s }},

		// ---- ACCIDENTAL: ordinary tools, not in the variant set ----
		{"hex-lower", plainSecret, "ACCIDENTAL", "xxd -p / od -An -tx1 / openssl", lowerHex},
		{"hex-upper", plainSecret, "ACCIDENTAL", "hexdump / many DB BLOB dumps", upperHex},
		{"hex-richSecret", richSecret, "ACCIDENTAL", "xxd -p of a keyfile", lowerHex},
		{"base32", plainSecret, "ACCIDENTAL", "TOTP seeds, some tokens", func(s string) string {
			return base32.StdEncoding.EncodeToString([]byte(s))
		}},
		{"html-entities", richSecret, "ACCIDENTAL", "API HTML error page reflecting a token via curl", html.EscapeString},
		{"json-slash-php", richSecret, "ACCIDENTAL", "PHP json_encode (escapes / as \\/)", func(s string) string {
			return strings.ReplaceAll(s, "/", `\/`)
		}},
		{"fold-wrapped-raw", plainSecret, "ACCIDENTAL", "fold -w8 / fmt / pr on a raw value", func(s string) string {
			var b strings.Builder
			for i, c := range s {
				if i > 0 && i%8 == 0 {
					b.WriteByte('\n')
				}
				b.WriteRune(c)
			}
			return b.String()
		}},
		// NOTE: bash 5.2 `set -x` uses single-quoting, which IS covered (verified
		// against real bash). Only `printf %q`'s backslash form escapes -- a
		// narrower case than xtrace.
		{"bash-printf-q", richSecret, "ACCIDENTAL", "bash printf %q (NOT set -x, which is covered)", bashPrintfQ},

		// ---- ADVERSARIAL: deliberate, documented as Not-prevented ----
		{"rev", plainSecret, "ADVERSARIAL", "| rev", func(s string) string { return reverse(s) }},
		{"upcase", plainSecret, "ADVERSARIAL", "| tr a-z A-Z", strings.ToUpper},
		{"space-out", plainSecret, "ADVERSARIAL", "| sed 's/./& /g'", func(s string) string {
			return strings.Join(strings.Split(s, ""), " ")
		}},
	}

	fmt.Printf("\n%-18s %-11s %-45s %s\n", "PROBE", "KIND", "TOOL", "RESULT")
	fmt.Println(strings.Repeat("-", 100))
	for _, p := range probes {
		enc := p.encode(p.secret)
		output := "prefix... " + enc + " ...suffix\n"
		// A leak = the *encoded form* still present after redaction (the secret
		// was recoverable from the model's view). For raw we check the raw value;
		// for encodings we check the encoded needle survived intact.
		var leaked bool
		if p.name == "raw" || p.name == "raw-richSecret" {
			leaked, _ = leaks(p.secret, output)
		} else {
			leaked, _ = survives(p.secret, enc, output)
		}
		status := "redacted"
		if leaked {
			status = ">>> LEAKED <<<"
		}
		fmt.Printf("%-18s %-11s %-45s %s\n", p.name, p.kind, p.tool, status)
	}
	fmt.Println()
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// bashPrintfQ approximates bash's printf %q for printable specials: backslash-
// escape shell metacharacters rather than wrap in single quotes.
func bashPrintfQ(s string) string {
	var b strings.Builder
	for _, c := range s {
		switch c {
		case ' ', '&', '<', '>', '|', ';', '(', ')', '$', '`', '"', '\'', '\\', '*', '?', '[', ']', '{', '}', '~', '!', '#':
			b.WriteByte('\\')
			b.WriteRune(c)
		default:
			b.WriteRune(c)
		}
	}
	return b.String()
}
