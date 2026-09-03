package config

import (
	"fmt"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/termsafe"
)

// refuseControl refuses an entry carrying a control character, whichever form
// it took. Every one of these is rendered into a deny rule, and the rendered
// file is one rule per line, so a newline in an entry ends the rule early and
// starts a second line with the rest of it. Neither half is the rule that was
// asked for, both halves are unbalanced regular expressions that will not
// compile, and a pattern that does not compile is skipped: the entry an
// operator added to refuse one more file takes the rules protecting the install
// with it, and nothing on the host reports the loss.
//
// The other controls do not split a rule and are refused for a second reason: a
// listing prints these back to a terminal, and a carriage return or an escape
// sequence in an entry makes the row read as something other than what is
// stored. Refused where they are written rather than escaped where they are
// shown, an entry being text an operator chose.
func refuseControl(form, value, at string) error {
	// Decoded byte by byte rather than ranged over: ranging yields U+FFFD for a
	// byte that is not valid UTF-8, which is not Actionable, so the check would
	// not see it. Such a byte renders a rule Go's regexp refuses to compile, and
	// the hook skips a rule it cannot compile, which is the same loss by a
	// quieter route.
	for i := 0; i < len(value); {
		r, size := utf8.DecodeRuneInString(value[i:])
		if r == utf8.RuneError && size == 1 {
			return fmt.Errorf("%s: %s %q has a byte at offset %d that is not valid UTF-8, so the rule it "+
				"renders would not compile and would refuse nothing", at, form, Shown(value), i)
		}
		if termsafe.Actionable(r) {
			return fmt.Errorf("%s: %s %q contains %q at offset %d. %s",
				at, form, Shown(value), r, i, whyControlIsRefused(r))
		}
		i += size
	}
	return nil
}

// whyControlIsRefused is which of the two reasons this character is refused
// for. The two are told apart because an operator reading that a tab splits a
// line goes looking for a line it did not split.
func whyControlIsRefused(r rune) string {
	if r == '\n' || r == '\r' {
		return "A rule is one line of a generated file, and this character ends " +
			"a line: it would split the rule and leave neither half working"
	}
	return "A listing prints an entry back to a terminal, and this character " +
		"would make the row read as something other than what is stored"
}

// Shown is an entry as a message quotes it back. Bounded because the entry is
// whatever was pasted at the flag, and a message that repeats it is as long as
// the paste: a mistyped argument otherwise answers with a hundred kilobytes,
// with the sentence that says what to do at the far end of it.
//
// Exported for the warnings an add prints alongside these refusals, which
// quote the same entries and are bounded by the same number.
func Shown(entry string) string { return termsafe.Truncate(entry, maxShownBytes) }

// maxShownBytes is enough of an entry to recognise which one was refused. Past
// PATH_MAX, so no path this could name is cut.
const maxShownBytes = 8192
