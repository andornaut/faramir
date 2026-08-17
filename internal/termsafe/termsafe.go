// Package termsafe renders caller-chosen text for a terminal, so the terminal
// displays it rather than obeying it.
//
// Two places print strings the coding agent chose to a terminal only root sees:
// the escalation prompt, which asks a human to grant that agent's command root,
// and `faramir logs`, which is where an operator goes to see what a command
// did.  A terminal acts on what it is sent, so text left raw in either is text
// that can rewrite what the reader is deciding on.
//
// Most of the danger is already gone by the time it gets here.  Everything
// recorded or handed to a question has been through redact.Feed, which strips
// CSI (including colour), OSC and the C0 controls.  What it does not strip:
//
//   - a bare "\r", CRLF alone being normalised to "\n".  It returns the cursor,
//     so the rest of the line overwrites what came before it.
//   - ESC followed by a byte outside @-Z and \-_, which no pattern there
//     matches.  That includes ESC c, a full terminal reset, which on many
//     emulators takes the scrollback with it.
//
// Either is enough to make a reader see something other than what was written,
// which for an audit log is the point of reading it.  So the rule here is
// applied to what survives rather than to what redaction already handles, and it
// is applied at the render, not at the source: the audit log on disk keeps the
// bytes as they were.
package termsafe

import (
	"strconv"
	"strings"
	"unicode/utf8"
)

// Arg renders one argument of a command.
//
// Ordinary arguments are returned unchanged, because a line full of quotation
// marks is one that is read less carefully.  Anything holding a control
// character, a space, a quote or a non-printable rune is quoted, which turns
// every such byte into a visible escape.
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
// so it is bounded as well as quoted: a question whose real content has scrolled
// off the top of a terminal is one nobody read, whichever field pushed it there.
func Field(value string, limit int) string {
	return Bound(Arg(value), limit)
}

// Line renders one line of recorded output.
//
// Escaped rather than quoted, and never bounded: this is the text an operator
// came to read, and wrapping every line in quotation marks or truncating it
// would make the log worse at the one job it has.  So only what a terminal would
// act on is escaped, and the rest, tabs included, is left as it was written.
func Line(line string) string {
	if strings.IndexFunc(line, unsafeRune) < 0 {
		return line
	}
	var b strings.Builder
	b.Grow(len(line))
	for _, r := range line {
		if unsafeRune(r) {
			// strconv.QuoteRune brings its own single quotes; the escape is what is
			// wanted, so they come off.
			b.WriteString(strings.Trim(strconv.QuoteRune(r), "'"))
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

// unsafeRune reports whether a terminal would act on this rune rather than draw
// it.  Tab is left alone: it is layout an operator wants, and it cannot move the
// cursor anywhere a reader would not expect.
//
// C1 (U+0080..U+009F) is here for the same reason C0 is, and it is not covered
// by the strip set: that matches CSI as ESC '[', so a child writing U+009B, the
// single-character form of the same introducer, reaches this unchanged, and a
// terminal honouring 8-bit controls reads "2J" as a screen clear.  Arg
// escapes these already, strconv.Quote treating them as non-printable; the two
// renderers agreeing is the point.
func unsafeRune(r rune) bool {
	return (r < 0x20 && r != '\t') || (r >= 0x7f && r <= 0x9f)
}

// Bound truncates on a rune boundary and says that it did.  Silent truncation
// would let a long value end the displayed text wherever it liked.
func Bound(text string, limit int) string {
	if len(text) <= limit {
		return text
	}
	// Backing off at most one rune, as internal/audit and internal/executor do
	// for the same job: scanning back for the first valid prefix would drop
	// everything after any invalid byte rather than just the partial rune at the
	// end.
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
	return cut + "... (" + strconv.Itoa(len(text)-len(cut)) +
		" more bytes; the audit record has all of it)"
}
