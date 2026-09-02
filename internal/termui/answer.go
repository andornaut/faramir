package termui

// Reading a yes or no from the operator. Two prompts take one: an escalation's
// question, and the confirmation `vault rm` puts before removing a file. Both
// are answered by one keystroke, so both are deny by default and both flush
// what was typed before the question was put.

import (
	"os"
	"strings"
	"unicode"

	"golang.org/x/sys/unix"
)

// FlushTypeahead drops input that arrived before a prompt was printed, so a
// keystroke meant for something else cannot answer it. This is what makes a
// one-character answer safe, and every prompt taking one has to call it.
//
// Terminals only, and it reports whether it flushed. Input that was not typed
// was not typed early: a substituted reader is a test's script and a redirected
// stdin is a file, and both are meant to be read in order.
func FlushTypeahead() bool {
	if !IsTerminal(os.Stdin) {
		return false
	}
	return unix.IoctlSetInt(int(os.Stdin.Fd()), unix.TCFLSH, unix.TCIFLUSH) == nil
}

// AnswerOf is the part of a line that carries the answer: what is left once the
// whitespace and unprintable bytes around it are gone. Empty is no answer at
// all. The edges only, so nothing is edited down into an approval it did not
// spell: "y<NUL>e" is a refusal, as it reads.
func AnswerOf(line string) string {
	return strings.TrimFunc(line, func(r rune) bool {
		return unicode.IsSpace(r) || !unicode.IsPrint(r)
	})
}

// Approves is deny by default: only an explicit y approves, and a typo, a
// stray word or a punctuation mark is a no, "yes" among them.
//
// One character, so one keystroke answers the prompt. That is what
// FlushTypeahead is for: input that arrived before the question was shown must
// not be able to spell the answer to it.
func Approves(line string) bool {
	return strings.ToLower(AnswerOf(line)) == "y"
}
