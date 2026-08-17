package audit

// What a string costs once json.Marshal has escaped it, and how to cut one to a
// budget counted that way.  The cap this serves is counted in the bytes the
// line actually spends, so every measurement here is in encoded bytes rather
// than in the bytes a command wrote.

import (
	"fmt"
	"unicode/utf8"
)

// Excerpt keeps the head and the tail of a command's output and says what it
// left out, measured in the bytes the record will spend rather than the bytes
// the command wrote.
//
// Head and tail rather than a prefix: what an operator wants from a long run is
// how it started and how it ended, and a prefix is the half that is never the
// answer.
func Excerpt(output string, budget int) (text string, dropped int) {
	if encodedLen(output) <= budget {
		return output, 0
	}
	head := prefixWithin(output, halfBudget(budget))
	tail := suffixWithin(output, halfBudget(budget))
	if len(head)+len(tail) >= len(output) {
		return output, 0
	}
	dropped = len(output) - len(head) - len(tail)
	return head + marker(dropped) + tail, dropped
}

// halfBudget is what each end of an excerpt may spend: the budget less room for
// the marker between them, split two ways.  Stated once because [Collector]
// fills the same two ends as a run streams and [Excerpt] fills them in one go,
// and two ends sized by different arithmetic would overrun the budget between
// them.
func halfBudget(budget int) int { return max((budget-markerReserve)/2, 1) }

func marker(dropped int) string {
	return fmt.Sprintf("\n[faramir: %d bytes of output dropped; the record cap "+
		"is what a record keeps]\n", dropped)
}

// encodedLen is what json.Marshal will spend on s inside a string, which is what
// the cap is counted in.  Six bytes for a byte a command picked, one for most of
// what it prints.
func encodedLen(s string) int {
	total := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		total += encodedRuneLen(r, size)
		i += size
	}
	return total
}

func encodedRuneLen(r rune, size int) int {
	switch {
	case r == '"' || r == '\\' || r == '\n' || r == '\r' || r == '\t':
		return 2
	case r < 0x20:
		return 6
	// HTML escaping is on for json.Marshal, so these three cost six apiece, which
	// is what makes a page of XML the cheapest way to write a very long line.
	case r == '<' || r == '>' || r == '&':
		return 6
	// An invalid byte is recorded as the escape \ufffd rather than as the three
	// bytes that rune encodes to, so it costs six like the rest of them.
	case r == utf8.RuneError && size == 1:
		return 6
	// Escaped by encoding/json whatever the settings are, for JSONP's sake.
	case r == '\u2028' || r == '\u2029':
		return 6
	}
	return size
}

// prefixWithin is the longest prefix of s whose encoded length fits in budget,
// ending on a rune boundary.
func prefixWithin(s string, budget int) string {
	spent := 0
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		cost := encodedRuneLen(r, size)
		if spent+cost > budget {
			return s[:i]
		}
		spent += cost
		i += size
	}
	return s
}

// suffixWithin is prefixWithin from the other end.
func suffixWithin(s string, budget int) string {
	spent := 0
	for i := len(s); i > 0; {
		r, size := utf8.DecodeLastRuneInString(s[:i])
		cost := encodedRuneLen(r, size)
		if spent+cost > budget {
			return s[i:]
		}
		spent += cost
		i -= size
	}
	return s
}
