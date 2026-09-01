package redact

// Eligibility: stage 3 of the pipeline documented on Package redact. A value
// too short to search for would match everywhere and eat the output, so it is
// refused rather than redacted badly.

import (
	"fmt"
	"strings"
)

// EligibilityPolicy is the one property of a value this decides: whether it is
// long enough to search output for.
//
// Length only: no distinct-character count and no entropy floor, neither being
// the strength check it reads as ("password" clears both). A short value
// matches inside ordinary words, so redacting it blanks unrelated output; a
// long low-entropy value such as "aaaaaaaa" mangles the operator's output
// rather than letting a value escape.
type EligibilityPolicy struct {
	MinLength int
}

// MaxValueBytes is the largest value the broker will hold. Two numbers meet
// here and the smaller one wins.
//
// The kernel's is 128 KiB: Linux caps one environment variable at
// MAX_ARG_STRLEN including the name and the "=", so a value at or over that
// can never be injected into a command at all.
//
// The broker's own is what actually binds. Every value enters an Aho-Corasick
// automaton whose states carry a dense transition table, so the set costs
// roughly 15 KB of memory per byte of secret, measured. A value at the
// kernel's cap would take the broker past 1.9 GB on its own, and nothing
// bounds it from there but the host: the broker is killed, and while it is
// down nothing is redacted at all.
//
// 16 KiB is above every credential this is for -- an SSH private key, a TLS
// chain, a kubeconfig with its embedded CAs, any API token -- and costs about
// 240 MB, which is a broker an operator can run. A credential larger than this
// is a file rather than a value: `faramir block --path` refuses it to the
// agent's file tools while a brokered command may still read it, which is the
// arrangement for a credential faramir should not be holding. `faramir link`
// is not the way around it, a linked value entering the same automaton.
const MaxValueBytes = 16 << 10

func DefaultPolicy() EligibilityPolicy {
	return EligibilityPolicy{MinLength: 8}
}

// Check returns "" if the value may be redacted, else the reason it may not.
func (p EligibilityPolicy) Check(value string) string {
	if len([]rune(value)) < p.MinLength {
		return fmt.Sprintf("shorter than %d characters", p.MinLength)
	}
	if len(value) >= MaxValueBytes {
		return fmt.Sprintf("%d bytes, and the broker holds at most %d: a value costs "+
			"about 15 KB of the broker's memory per byte, so one this size is a "+
			"broker the host kills. Refuse the file to the agent with `sudo faramir "+
			"block --path` and let a brokered command read it instead",
			len(value), MaxValueBytes)
	}
	// A value that is faramir's own token, guillemets and all. The redactor
	// emits that shape for another ref, so a stored token in output cannot be
	// told from a token the redactor wrote, and wherever it is matched it is
	// re-wrapped: the output would carry this ref's token instead of the one it
	// held. Refused the way a short value is, being a value the redactor
	// cannot represent rather than one it will not hold. No real credential is
	// this shape; it is faramir's reserved output format.
	if strings.HasPrefix(value, tokenOpen) && strings.HasSuffix(value, tokenClose) {
		return "is shaped like faramir's own " + tokenOpen + "…" + tokenClose +
			" token, which the redactor emits and would re-wrap"
	}
	return ""
}

// The delimiters of the token a secret is replaced with. Named so Check refuses
// exactly the shape TokenFor produces.
const (
	tokenOpen  = "«SECRET:"
	tokenClose = "»"
)

// TokenFor is the placeholder a secret is replaced with, stable across turns
// and processes so the model can reason about a value without seeing it.
func TokenFor(ref string) string { return tokenOpen + ref + tokenClose }
