package denyrules

// The rules built over a command name rather than a path.

import (
	"regexp"
	"strings"
)

// CommandPosition is what may stand in front of a command on a line: the start
// of it, a separator, an opening quote, and the prefixes that run something
// else.
//
// Anchored rather than matched anywhere, which is the difference between an
// entry being safe to write and being safe to write only if it is long enough.
// "pass" matched inside "--ask-become-pass" before this, because a hyphen is a
// non-word byte and \b holds beside it, so whether a one-word entry was usable
// depended on whether some flag on some host happened to carry the word. That
// is not a question an operator can answer about a fleet.
//
// The trade is the other way round from what it replaces: matching anywhere had
// no holes and refused ordinary work, `grep 'pass show' defaults.yml` included.
// This refuses none of that and misses a command reached through a prefix
// nobody listed. That is the better error for a list the design already says is
// not the boundary: it catches an accident, and an accident is typed rather
// than wrapped. A refusal of real work is what gets a deny list turned off.
//
// RE2 has no lookbehind, so what precedes is consumed rather than asserted.
const CommandPosition = `(?:^|[;&|(){}\n])\s*` +
	// Anything that runs something else, repeated: `sudo nice op read` is the
	// command at a position two prefixes deep.
	//
	// A flag may take an argument, so one bare word after a flag is allowed to
	// belong to it: that is what makes `sudo -u me op read` reach the command.
	// RE2 finds a match where one exists, so the same expression still matches
	// `sudo -n op read`, where the word after the flag is the command itself.
	`(?:(?:sudo|doas|nohup|time|command|xargs|stdbuf|nice|ionice)(?:\s+-\S+(?:\s+\S+)?)*\s+` +
	`|env(?:\s+\S+=\S+)*\s+` +
	`|\S+=\S+\s+` +
	// A shell given a command string, where the opening quote is what the
	// command starts after. Named rather than allowing any quote: a bare quote
	// would put `grep -r 'op read' defaults.yml` back at a command position,
	// which is the refusal of ordinary work this change exists to stop.
	`|(?:ba|z|da|k)?sh\s+-\S*c\S*\s+['"` + "`" + `]?)*`

// CommandPathPrefix is a directory in front of the first word, which is the
// same command spelled with its path: an operator writing `op read` means the
// program, and `/usr/bin/op read` is it. Without this the one an agent reaches
// for after meeting the refusal is the one that is not refused.
//
// The group has to end in a separator, so it takes a path and nothing else, and
// the anchor in front of it still holds: a word inside an argument is no more a
// command than it was, and `--ask-become-pass` carries no separator to match on.
const CommandPathPrefix = `(?:\S*/)?`

// CommandRule is a declared command as the rules match it: the words taken
// literally, any run of whitespace between them, and a word boundary at each
// end that has one.
//
// The words rather than a regular expression the operator writes. A pattern
// language here would be a second thing to get wrong in a file that decides
// what an agent may run, and the failure is silent in both directions: one that
// matches too much refuses ordinary work, and one that matches too little reads
// exactly like one that works.
func CommandRule(command string) string {
	words := strings.Fields(command)
	if len(words) == 0 {
		return ""
	}
	quoted := make([]string, 0, len(words))
	for _, word := range words {
		quoted = append(quoted, regexp.QuoteMeta(word))
	}
	rule := CommandPosition + CommandPathPrefix + strings.Join(quoted, `\s+`)
	if last := words[len(words)-1]; isWordByte(last[len(last)-1]) {
		rule += `\b`
	}
	return rule
}

// isWordByte reports whether \b means anything beside this byte. "\b-d" never
// matches, a hyphen being a non-word character on both sides.
func isWordByte(b byte) bool {
	return b == '_' ||
		(b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}
