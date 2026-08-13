package redact

import (
	"encoding/base32"
	"encoding/hex"
	"strings"
	"testing"
)

// A battery of output encodings thrown at the redactor. Each case names the real
// tool that produces that encoding and whether it is plausibly ACCIDENTAL
// (ordinary tool output, which docs/redaction.md claims to prevent) or
// ADVERSARIAL (a deliberate transform, documented there as not prevented).

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
		// against real bash). Only `printf %q`'s backslash form escapes: a deliberate
		// re-quoting, narrower than the accidental xtrace path.
		{"bash-printf-q", richSecret, "DELIBERATE", "bash printf %q (NOT set -x, which is covered)", bashPrintfQ},

		// ---- ADVERSARIAL: deliberate, documented as Not-prevented ----
		{"rev", plainSecret, "ADVERSARIAL", "| rev", reverse},
		{"upcase", plainSecret, "ADVERSARIAL", "| tr a-z A-Z", strings.ToUpper},
		{"space-out", plainSecret, "ADVERSARIAL", "| sed 's/./& /g'", func(s string) string {
			return strings.Join(strings.Split(s, ""), " ")
		}},
	}

	for _, p := range probes {
		enc := p.encode(p.secret)
		output := "prefix... " + enc + " ...suffix\n"
		// A leak is the encoded form still present after redaction, the secret
		// being recoverable from the model's view. For raw that is the value
		// itself; for an encoding it is whether the encoded needle survived.
		var leaked bool
		if p.name == "raw" || p.name == "raw-richSecret" {
			leaked, _ = leaks(p.secret, output)
		} else {
			leaked, _ = survives(p.secret, enc, output)
		}

		// Both directions are asserted, so this is a boundary rather than a note.
		// A row that starts being caught fails here, which is the signal to move
		// it up to the covered set deliberately.
		switch p.kind {
		case "COVERED", "ACCIDENTAL":
			if leaked {
				t.Errorf("%s (%s): expected redaction, secret form leaked", p.name, p.tool)
			}
		default:
			if !leaked {
				t.Errorf("%s (%s) is now covered. That is an improvement, not a "+
					"regression: move it to the ACCIDENTAL set and say so in "+
					"docs/redaction.md", p.name, p.tool)
			}
		}
	}
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
