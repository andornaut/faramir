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
// Where the line cannot be read this way the whole of it is returned as one
// segment. A longer segment matches everything a shorter one would and more, so
// an unterminated quote, or any shape not accounted for here, costs a refusal
// that need not have happened rather than letting one through.
func Segments(line string) []string {
	var (
		out   []string
		start int
		// The quote in force, or 0 outside one.
		quote byte
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
		case c == '|' || c == ';' || c == '\n':
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
	// that split it would be one that refused less.
	if quote != 0 {
		return []string{strings.TrimSpace(line)}
	}
	cut(len(line), len(line))
	return out
}

// redirection reports whether the "&" at i belongs to a redirection operator
// rather than ending a command.
func redirection(line string, i int) bool {
	if i > 0 && line[i-1] == '>' {
		return true
	}
	return i+1 < len(line) && line[i+1] == '>'
}
