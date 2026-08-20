package audit

// What a string costs once json.Marshal has escaped it, and how to cut one to a
// budget counted that way. The cap this serves is counted in the bytes the
// line actually spends, so every measurement here is in encoded bytes rather
// than in the bytes a command wrote.

import (
	"encoding/json"
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
// the marker between them, split two ways. Stated once because [Collector]
// fills the same two ends as a run streams and [Excerpt] fills them in one go,
// and two ends sized by different arithmetic would overrun the budget between
// them.
func halfBudget(budget int) int { return max((budget-markerReserve)/2, 1) }

func marker(dropped int) string {
	return fmt.Sprintf("\n[faramir: %d bytes of output dropped; the record cap "+
		"is what a record keeps]\n", dropped)
}

// invalidByteLen is what the encoder linked into this binary spends on one
// invalid byte, measured from the encoder itself at startup.
//
// The other costs in encodedRuneLen are fixed by the JSON grammar; this one is
// the encoder's choice and has differed between Go releases. Measuring it is
// what keeps the cap counted in the unit the line is actually written in, on
// whichever toolchain built this.
var invalidByteLen = measureInvalidByteLen()

func measureInvalidByteLen() int {
	line, err := json.Marshal("\xff")
	if err != nil {
		// Unreachable: a string always marshals. Six is the wider of the two
		// answers a Go release has given, and the safer way to be wrong: encode
		// marshals and checks, so what over-counting costs is output, while
		// under-counting costs the record's other fields.
		return 6
	}
	// Less the two quotes the marshalled form carries.
	return len(line) - 2
}

// encodedLen is what json.Marshal will spend on s inside a string, which is what
// the cap is counted in. Six bytes for most of what a command picks, one for
// most of what it prints.
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
	// An invalid byte is replaced by U+FFFD, which the encoder either escapes as
	// \ufffd or writes as the rune itself. Which one is asked of the encoder
	// rather than assumed: guess high and Excerpt drops output that would have
	// fitted, guess low and the record overshoots the cap on the first marshal
	// and is reduced, which cuts every other field to save the one that was
	// mismeasured.
	case r == utf8.RuneError && size == 1:
		return invalidByteLen
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
