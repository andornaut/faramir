package redact

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

// survives reports whether needle is still present after the redactor has been
// over output holding secret.
func survives(secret, needle, output string) bool {
	r := New([]Secret{{Ref: "svc/token", Value: secret}}, DefaultPolicy())
	return strings.Contains(r.RedactText(output), needle)
}

// A battery of output encodings thrown at the redactor.  Each case names the
// real tool that produces it and whether docs/redaction.md claims to cover it.
//
// Both directions are asserted, so this is a boundary rather than a note: a row
// documented as uncovered that starts being caught fails here too, which is the
// signal to move it deliberately.
func TestAdversarialBattery(t *testing.T) {
	// Two secrets: one alphanumeric (exercises hex and case), one with the
	// URL, shell and HTML metacharacters real credentials contain.
	const (
		plainSecret = "hunter2correcthorsebatteryZ9" // >= min_length, alnum
		richSecret  = "p@ss/w0rd+tok=v&x<y>z"        // / & < > + = @
	)
	lowerHex := func(s string) string { return hex.EncodeToString([]byte(s)) }
	upperHex := func(s string) string { return strings.ToUpper(hex.EncodeToString([]byte(s))) }

	for _, p := range []struct {
		name string
		// tool is what produces this form in ordinary use, which is what makes
		// covering it worth the variant.
		tool    string
		secret  string
		covered bool
		encode  func(string) string
	}{
		{"raw", "anything", plainSecret, true, func(s string) string { return s }},
		{"raw with metacharacters", "anything", richSecret, true, func(s string) string { return s }},

		// Ordinary tool output, which docs/redaction.md claims to prevent.
		{"hex lower", "xxd -p / od -An -tx1 / openssl", plainSecret, true, lowerHex},
		{"hex upper", "hexdump / many DB BLOB dumps", plainSecret, true, upperHex},
		{"hex with metacharacters", "xxd -p of a keyfile", richSecret, true, lowerHex},
		{"base32", "TOTP seeds, some tokens", plainSecret, true, func(s string) string {
			return base32.StdEncoding.EncodeToString([]byte(s))
		}},
		{"base32 unpadded", "a token format that drops the padding", plainSecret, true, func(s string) string {
			return strings.TrimRight(base32.StdEncoding.EncodeToString([]byte(s)), "=")
		}},
		{"json escaped slash", "PHP json_encode, which escapes / as \\/", richSecret, true, func(s string) string {
			return strings.ReplaceAll(s, "/", `\/`)
		}},
		{"line-wrapped raw", "fold -w8 / fmt / pr on a raw value", plainSecret, true, func(s string) string {
			var b strings.Builder
			for i, c := range s {
				if i > 0 && i%8 == 0 {
					b.WriteByte('\n')
				}
				b.WriteRune(c)
			}
			return b.String()
		}},

		// Deliberate transforms, documented as not prevented.  bash 5.2 `set -x`
		// single-quotes and is covered; only printf %q's backslash form escapes,
		// which is a re-quoting rather than the accidental xtrace path.
		{"bash printf %q", "bash printf %q, not set -x", richSecret, false, bashPrintfQ},
		{"reversed", "| rev", plainSecret, false, reverse},
		{"upper-cased", "| tr a-z A-Z", plainSecret, false, strings.ToUpper},
		{"spaced out", "| sed 's/./& /g'", plainSecret, false, func(s string) string {
			return strings.Join(strings.Split(s, ""), " ")
		}},
	} {
		t.Run(p.name, func(t *testing.T) {
			encoded := p.encode(p.secret)
			leaked := survives(p.secret, encoded, "prefix... "+encoded+" ...suffix\n")
			switch {
			case p.covered && leaked:
				t.Errorf("%s survived redaction; produced by %s", p.name, p.tool)
			case !p.covered && !leaked:
				t.Errorf("%s is now covered, which is an improvement rather than a "+
					"regression: mark it covered here and say so in docs/redaction.md",
					p.name)
			}
		})
	}
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}

// bashPrintfQ approximates bash's printf %q for printable specials:
// backslash-escape shell metacharacters rather than wrap in single quotes.
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
