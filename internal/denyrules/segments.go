package denyrules

import "strings"

// Segments splits a command line into the commands it runs, so a rule matched
// against one of them cannot reach out of it. A reader in one command says
// nothing about a path named in another, and a pattern matched against the
// whole line cannot tell the two apart: it sees one string.
//
// Split at an unquoted "|", ";", "&" or newline. Quoting is what a pattern
// cannot do for itself, and it is the whole reason this exists rather than a
// character class: `python3 -c 'import os; open("k")'` is one command carrying
// a semicolon in an argument, and `head -20 "a.txt"; echo "k"` is two commands
// where the quotes belong to the first.
//
// The body of a quoted heredoc is skipped: `<<'EOF'` and `<<"EOF"` make every
// line up to the terminator literal data, so a body naming a command is a file
// being written rather than a command being run. Only the quoted spelling. An
// unquoted `<<EOF` expands `$(...)` and backticks in its body, which is a
// command, so those bodies are read as commands exactly as before.
//
// Where the line cannot be read this way the whole of it is returned as one
// segment. A longer segment matches everything a shorter one would and more, so
// an unterminated quote, a heredoc whose terminator never arrives, or any shape
// not accounted for here, costs a refusal that need not have happened rather
// than letting one through.
func Segments(line string) []string {
	var (
		out   []string
		start int
		// The quote in force, or 0 outside one.
		quote byte
		// The quoted heredocs opened on the line being read, in the order their
		// bodies arrive. Bash takes them at the next newline, one body after
		// another, which is why this is a queue rather than a single delimiter.
		pending []heredoc
	)
	cut := func(end, next int) {
		if segment := strings.TrimSpace(line[start:end]); segment != "" {
			out = append(out, segment)
		}
		start = next
	}
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quote == '\'':
			// A single-quoted string ends at the next quote and holds no escapes.
			if c == '\'' {
				quote = 0
			}
		case quote == '"':
			if c == '\\' && i+1 < len(line) {
				i++
				continue
			}
			if c == '"' {
				quote = 0
			}
		case c == '\\' && i+1 < len(line):
			// Outside quotes a backslash takes the next character with it, a
			// newline among them: that is one command written over two lines.
			i++
		case c == '\'' || c == '"':
			quote = c
		case c == '<' && i+1 < len(line) && line[i+1] == '<':
			// A "<<<" herestring is stepped over whole rather than declined. Its word
			// is data on this line and no body follows, so there is nothing here to
			// skip; and leaving i on the first "<" has the next pass read the second
			// and third as a "<<" whose quoted word is indistinguishable from a
			// delimiter. Everything up to a line matching that word would then be
			// skipped as the body of a heredoc that was never opened, and the
			// commands in it would never be matched against the deny list.
			if i+2 < len(line) && line[i+2] == '<' {
				i += 2
				continue
			}
			// Only the quoted spelling is taken, and only its own token is stepped
			// over: an unquoted delimiter and anything this cannot read leave i where
			// it was, so the body is read as commands.
			if doc, end, ok := heredocOpen(line, i); ok {
				pending = append(pending, doc)
				i = end - 1
			}
		case c == '\n':
			cut(i, i+1)
			if len(pending) > 0 {
				end, ok := skipBodies(line, i+1, pending)
				if !ok {
					// A terminator that never arrives leaves the rest of the line
					// unreadable, so none of it is split.
					return []string{strings.TrimSpace(line)}
				}
				pending = pending[:0]
				start, i = end, end-1
			}
		case c == '|' || c == ';':
			cut(i, i+1)
		case c == '&':
			// ">&" and "&>" are redirection rather than backgrounding, so the
			// command carries on. Read from the text either side, both spellings
			// being one operator.
			if redirection(line, i) {
				continue
			}
			cut(i, i+1)
		}
	}
	// An unterminated quote leaves the reader of this line guessing, and a guess
	// that split it would be one that refused less. A heredoc still waiting for
	// its body is the same: the line ended before the redirection was satisfied.
	if quote != 0 || len(pending) > 0 {
		return []string{strings.TrimSpace(line)}
	}
	cut(len(line), len(line))
	return out
}

// heredoc is one `<<'DELIM'` redirection waiting for its body.
type heredoc struct {
	delim string
	// tabs is `<<-`, which lets the terminator be indented with tabs.
	tabs bool
}

// heredocOpen reads the redirection starting at the "<<" at i. It reports the
// heredoc and the index just past the delimiter token, and false for anything
// but a quoted delimiter: an unquoted one, an unterminated quote, or a
// delimiter holding a newline, which is a shape this cannot read.
//
// A "<<<" herestring never reaches here, its caller stepping over the whole
// token: read from the second "<" this would take the herestring's own quoted
// word for a delimiter.
func heredocOpen(line string, i int) (heredoc, int, bool) {
	j := i + 2
	var doc heredoc
	if j < len(line) && line[j] == '-' {
		doc.tabs = true
		j++
	}
	for j < len(line) && (line[j] == ' ' || line[j] == '\t') {
		j++
	}
	if j >= len(line) || (line[j] != '\'' && line[j] != '"') {
		return heredoc{}, 0, false
	}
	q := line[j]
	// The delimiter is taken literally between the quotes, which is what bash
	// does with it: no escapes, and the closing quote ends it.
	end := strings.IndexByte(line[j+1:], q)
	if end < 0 {
		return heredoc{}, 0, false
	}
	doc.delim = line[j+1 : j+1+end]
	if doc.delim == "" || strings.ContainsRune(doc.delim, '\n') {
		return heredoc{}, 0, false
	}
	return doc, j + end + 2, true
}

// skipBodies steps over the bodies of every heredoc opened on the line that
// just ended, in the order bash reads them, and reports the index of the first
// character after the last terminator. False where a terminator never arrives.
func skipBodies(line string, from int, docs []heredoc) (int, bool) {
	at := from
	for _, doc := range docs {
		found := false
		for at <= len(line) {
			end := strings.IndexByte(line[at:], '\n')
			text := line[at:]
			next := len(line)
			if end >= 0 {
				text = line[at : at+end]
				next = at + end + 1
			}
			// The terminator is the whole line, which is what bash requires of it.
			// `<<-` strips leading tabs and nothing else, so spaces still make a
			// line that does not terminate.
			if doc.tabs {
				text = strings.TrimLeft(text, "\t")
			}
			at = next
			if text == doc.delim {
				found = true
				break
			}
			if end < 0 {
				break
			}
		}
		if !found {
			return 0, false
		}
	}
	return at, true
}

// redirection reports whether the "&" at i belongs to a redirection operator
// rather than ending a command.
func redirection(line string, i int) bool {
	if i > 0 && line[i-1] == '>' {
		return true
	}
	return i+1 < len(line) && line[i+1] == '>'
}
