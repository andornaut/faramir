// Package termsafe renders caller-chosen text for a terminal, so the terminal
// displays it rather than obeying it.
//
// Two places print strings the coding agent chose to a terminal only root sees:
// the escalation prompt, and `faramir logs`. Everything recorded or handed to
// a question has been through redact.Feed, which strips CSI (including colour),
// OSC and the C0 controls. What it does not strip:
//
//   - a bare "\r", CRLF alone being normalised to "\n". It returns the cursor,
//     so the rest of the line overwrites what came before it.
//   - ESC followed by a byte outside @-Z and \-_, which no pattern there
//     matches. That includes ESC c, a full terminal reset, which on many
//     emulators takes the scrollback with it.
//
// So the rule here covers what survives redaction, and is applied at the render
// rather than at the source: the audit log on disk keeps the bytes as they
// were.
package termsafe

import (
	"fmt"
	"strconv"
	"strings"
	"unicode/utf8"
)

// Arg renders one argument of a command. Ordinary arguments are returned
// unchanged, a line full of quotation marks being read less carefully; anything
// holding a control character, a space, a quote or a non-printable rune is
// quoted, which turns every such byte into a visible escape.
func Arg(arg string) string {
	if arg == "" {
		return `""`
	}
	quoted := strconv.Quote(arg)
	if quoted == `"`+arg+`"` && !strings.ContainsAny(arg, " \t") {
		return arg
	}
	return quoted
}

// Field is Arg for one field of a prompt rather than one argument of a command,
// so it is bounded as well as quoted: a question whose content has scrolled off
// the top of a terminal is one nobody read.
//
// Bound, so the cut points at the audit record. For text with no record beside
// it, compose Truncate with Arg instead rather than telling the reader to go
// and look up something that was never written.
func Field(value string, limit int) string {
	return Bound(Arg(value), limit)
}

// Line renders one line of recorded output. Escaped rather than quoted, and
// never bounded: this is the text an operator came to read, so only what a
// terminal would act on is escaped and the rest, tabs included, is left as it
// was written.
func Line(line string) string {
	if strings.IndexFunc(line, unsafeRune) < 0 && utf8.ValidString(line) {
		return line
	}
	var b strings.Builder
	b.Grow(len(line))
	// Ranged by index rather than by rune, because a byte that is not valid UTF-8
	// is not the rune it would have encoded. Ranging yields U+FFFD for it and
	// writing that back would drop the byte; testing U+FFFD against unsafeRune
	// says it is safe and writes the original byte straight through. Either way
	// a lone 0x9b, the single-character form of the CSI introducer, would reach a
	// terminal that honours 8-bit controls and be read as the start of a
	// sequence. Output arrives here through the redactor, which replaces an
	// invalid byte already; a recorded path or a detail string does not.
	for i := 0; i < len(line); {
		r, size := utf8.DecodeRuneInString(line[i:])
		if r == utf8.RuneError && size == 1 {
			fmt.Fprintf(&b, `\x%02x`, line[i])
			i++
			continue
		}
		if unsafeRune(r) {
			// strconv.QuoteRune brings its own single quotes; the escape is what is
			// wanted, so they come off.
			b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
			i += size
			continue
		}
		b.WriteString(line[i : i+size])
		i += size
	}
	return b.String()
}

// unsafeRune reports whether a terminal would act on this rune rather than draw
// it. Tab is left alone, being layout an operator wants.
//
// C1 (U+0080..U+009F) is here for the same reason C0 is, and is not covered by
// the strip set: that matches CSI as ESC '[', so a child writing U+009B, the
// single-character form of the same introducer, reaches this unchanged, and a
// terminal honouring 8-bit controls reads "2J" as a screen clear. Arg
// escapes these already, strconv.Quote treating them as non-printable.
func unsafeRune(r rune) bool { return r != '\t' && Actionable(r) }

// Actionable reports whether a terminal would act on this rune rather than draw
// it: the C0 controls, DEL, and the C1 block, which carries the
// single-character forms of the same introducers ESC begins.
//
// Exported because it is also what may not be written into a rule. A subject
// carrying one of these is refused where it is written rather than escaped
// where it is shown, and two packages deciding that separately is two lists
// that agree until one of them is edited.
func Actionable(r rune) bool {
	return r < 0x20 || (r >= 0x7f && r <= 0x9f)
}

// Bound truncates on a rune boundary and says that it did: silent truncation
// would let a long value end the displayed text wherever it liked. For text
// that has a record beside it; Truncate is the same cut for text that does
// not.
func Bound(text string, limit int) string {
	cut, dropped := cutRunes(text, limit)
	if dropped == 0 {
		return text
	}
	return cut + "... (" + strconv.Itoa(dropped) +
		" more bytes; the audit record has all of it)"
}

// Truncate is Bound for text printed to a terminal and written nowhere else,
// where there is no record to point the reader at. A message quoting what it
// was given is as long as what it was given: a pasted key file is a hundred
// kilobytes of refusal.
func Truncate(text string, limit int) string {
	cut, dropped := cutRunes(text, limit)
	if dropped == 0 {
		return text
	}
	return cut + "... (" + strconv.Itoa(dropped) + " more bytes)"
}

// cutRunes is the cut both make: the first limit bytes, backed off to a rune
// boundary, and how many bytes that left behind.
func cutRunes(text string, limit int) (string, int) {
	if len(text) <= limit {
		return text, 0
	}
	// Backing off at most one rune, as internal/audit and internal/executor do:
	// scanning back for the first valid prefix would drop everything after any
	// invalid byte rather than the partial rune at the end.
	cut := text[:limit]
	for i := 1; i < utf8.UTFMax && i <= len(cut); i++ {
		start := len(cut) - i
		if !utf8.RuneStart(cut[start]) {
			continue
		}
		if !utf8.ValidString(cut[start:]) {
			cut = cut[:start]
		}
		break
	}
	return cut, len(text) - len(cut)
}
