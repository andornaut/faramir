package termui

import "testing"

// Deny by default, at the last place a human's answer is read: only an explicit
// y approves, so a typo, a stray word or a punctuation mark refuses. "yes" is
// among the refusals: one token approves, and a second spelling of it is a
// second thing to get wrong.
func TestOnlyYApproves(t *testing.T) {
	// The last two are what a terminal puts around an answer rather than part of
	// one: the newline it is read up to, and the carriage return of a CRLF ending.
	for _, line := range []string{"y", "Y", " y ", "y\n", "y\r\n"} {
		if !Approves(line) {
			t.Errorf("%q did not approve", line)
		}
	}
	for _, line := range []string{"no", "n", "yes", "YES", "", "\n", "y e s", "sure", "y please", "ok", "1"} {
		if Approves(line) {
			t.Errorf("%q approved an escalation", line)
		}
	}
}

// Only the edges are stripped, so nothing is edited down into an approval it did
// not spell: a line needing an unprintable byte removed from the middle of it to
// read as "y" was not somebody typing y.
func TestAnInteriorUnprintableIsNotEditedIntoAnApproval(t *testing.T) {
	for _, line := range []string{"y\x00e", "y\re", "y\x1bs", "y\x00es"} {
		if Approves(line) {
			t.Errorf("%q approved an escalation", line)
		}
	}
}

// What holds nothing printable is not an answer and must not be counted as a
// no: an unanswered question is left to expire rather than being spent by a
// stray newline. A punctuation mark is an answer, and so a refusal: an
// operator who types "?" is owed the question closing.
func TestABlankLineIsNotAnAnswer(t *testing.T) {
	for _, line := range []string{"", "\n", "   \n", "\t\r\n", "\x1b\n"} {
		if AnswerOf(line) != "" {
			t.Errorf("%q was read as an answer", line)
		}
	}
	for _, line := range []string{"no\n", "y\n", "?\n"} {
		if AnswerOf(line) == "" {
			t.Errorf("%q was not read as an answer", line)
		}
	}
}
