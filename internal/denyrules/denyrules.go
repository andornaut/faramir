// Package denyrules holds the command vocabulary the guard's path rules are
// built from, and the shape those rules take.
//
// Its own package because both sides need it and neither may import the other:
// internal/install renders the shipped pattern file from the protected set it
// already holds, and internal/guard builds the same rules at run time for a
// config directory the file did not name. A copy in each would be two lists
// that agree until one of them is edited.
package denyrules

import (
	"path"
	"regexp"
	"strings"
)

// The command alternations the path rules share. Readers carry interpreters and
// copiers as well as pagers: reading a key with python, or copying it somewhere
// unmatched and reading it there, is the same disclosure. "sed" is a writer
// only; "grep" is neither, so naming a .env file in a search is not refused.
//
// The decryption tools are readers and writers both, and they are here rather
// than as verb rules of their own: `sops -d` on this install's store is a read
// of it, and `sops -d` on somebody else's file is that host's business. Keeping
// them in the vocabulary refuses the first and leaves the second, where a rule
// on the verb refused every use of the tool anywhere.
// The list is generous because it costs nothing to be: a rule fires only where
// one of these appears together with a path this host protects, so a word here
// refuses nothing an agent does anywhere else. What decided the additions is
// whether the tool prints a file's contents or makes a copy to read elsewhere:
// `sort FILE` and `diff /dev/null FILE` print it as surely as `cat` does, and
// `find DIR -exec` reaches every file under it. A hash is deliberately absent,
// a transform of a value being the exfiltration the design says it cannot cover.
const (
	ReadCommands = `\b(?-i:` + gnuPrefix + `(?:cat|less|more|head|tail|bat|xxd|od|` +
		`strings|base64|base32|hexdump|uuencode|rev|tac|awk|cut|nl|dd|jq|yq|` +
		`python3?|perl|ruby|tee|cp|tar|scp|rsync|sops|age|ansible-vault|sort|` +
		`uniq|comm|join|paste|column|fold|expand|unexpand|fmt|pr|shuf|split|` +
		`csplit|diff|find|install|cpio|zcat|gunzip|bzcat|xzcat|zstdcat|` +
		`openssl))\b`
	WriteCommands = `\b(?-i:` + gnuPrefix + `(?:rm|shred|truncate|mv|cp|tee|dd|sed|` +
		`chmod|chown|chgrp|setfacl|ln|sops|age|ansible-vault|install|split|` +
		`csplit|cpio|gzip|bzip2|xz|zstd))\b`

	// MoveCommands is the rest of what puts a file's contents somewhere else:
	// under another name, at another path, or in another encoding. Every other
	// way of doing that is a reader already -- cp, tee, dd, tar, cpio, split and
	// the decryption tools are in both vocabularies -- so this is what is left.
	//
	// It exists because "reads it" and "changes it" is not the whole of the
	// question a brokered command asks. `mv key /tmp/x` and `ln -s key /tmp/x`
	// disclose nothing themselves and leave the file readable under a name no
	// rule was written for, which is the same disclosure one step later. `sed`
	// is here rather than among the readers for the same reason it is a writer
	// there, and it prints a file as surely as cat does: `sed -n p key`. The
	// compressors re-encode in place, which walks a declared path out from under
	// a rule that named it.
	MoveCommands = `\b(?-i:` + gnuPrefix + `(?:mv|ln|sed|gzip|bzip2|xz|zstd))\b`
)

// gnuPrefix takes the name a tool has where it is not the default one. Ubuntu
// 26.04 ships uutils as `cat` and the GNU build as `gnucat`, and does that for
// 104 programs, 18 of which are in the vocabulary above. A word boundary does
// not fall inside `gnucat`, so every one of those walked past these rules on
// that release: `gnucat /etc/faramir/age.key` reached the EACCES the deny list
// exists to answer instead of.
//
// Optional, so the ordinary names still match, and only this prefix: a rule
// fires only where one of these words meets a path this host protects, so
// taking a name that is not installed refuses nothing an agent does elsewhere.
const gnuPrefix = `(?:gnu)?`

// NormalizePaths rewrites the path-looking words of a command into their
// shortest spelling, so a rule written for /home/you/.aws also refuses
// /home/you//.aws and /home/you/../you/.aws. Matched in addition to the command
// as it was typed, never instead of it: cleaning can only shorten a word, so a
// rule that matched the original still matches, and the pair together refuses
// more than either alone.
//
// Words rather than the whole string: a path ends at whitespace or a shell
// separator, and joining across one would invent a path nobody wrote. What this
// does not reach is a path assembled at run time -- a relative one after a `cd`,
// or a variable expanded by the shell -- which needs the cwd this never has.
func NormalizePaths(command string) string {
	return pathWord.ReplaceAllStringFunc(command, func(word string) string {
		// Only the two spellings this exists for, so a word that is already
		// shortest is returned untouched and the common case allocates nothing.
		if !strings.Contains(word, "//") && !strings.Contains(word, "..") {
			return word
		}
		cleaned := path.Clean(word)
		// Clean turns "" and "." into ".", and drops a leading "./", which would
		// make a bare word out of something that was written as a path.
		if cleaned == "." || !strings.Contains(cleaned, "/") {
			return word
		}
		return cleaned
	})
}

// pathWord is a run of characters holding a "/" and stopping where a shell word
// stops. The class matches PathEnd's, so what counts as the end of a path is
// one answer rather than two.
var pathWord = regexp.MustCompile(`[^\s"';&|()]*/[^\s"';&|()]*`)

// Binding is a path bound to a shell variable, by an assignment or by the list
// of a for loop. The rules above read left to right, so a command has to appear
// before the path it reaches: `cat ~/.ssh/id_rsa` is refused and
// `p=~/.ssh/id_rsa; cat $p` is not, the reader arriving after the only mention
// of the file. Matching the binding refuses naming the path at all, whatever is
// done with the variable afterwards.
//
// Both forms, because the loop is the one that is written by accident: walking
// a set of directories and reading something in each is ordinary, and it
// reaches every file the direct spelling is refused.
//
// An assignment's value is one word, ending at the first unquoted space, or a
// quoted string, which holds spaces and ends at the closing quote. Both, or a
// path quoted because it has a space in it would be named here and not seen,
// while the read rules a few lines up cross the same space with ArgSpan.
// "Local Storage" is such a path, and the reason the bare form is not enough.
//
// What keeps the quoted form from reaching prose is PathStartBound rather than
// anything here: a name may not open after a space, so a sentence that says one
// is left alone while a path anywhere inside the quotes is not.
//
// A for list runs to the end of the command, so it stops at a separator.
const Binding = `(?:\b[A-Za-z_][A-Za-z0-9_]*=(?:["'][^"']*|\S*)` +
	`|\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+[^;&|]*)`

// PathEnd is what may follow a path in a command line: whitespace, a quote, a
// separator, or the end of it. A class rather than \b, and shared so the two
// sides bound a path the same way: "\b" holds beside a hyphen, so a rule for
// /opt/faramir would match /opt/faramir-notes.md and refuse a sibling that
// merely starts the same way.
const PathEnd = `[\s"';&|)]|$`

// ArgSpan is what a rule crosses between a command and a path it reaches: the
// arguments in between.
//
// Everything, because a rule is matched against one command rather than against
// a whole line: Segments is what decides where a command ends, and it reads the
// quoting a pattern cannot. A class that stopped at a pipe would stop at one
// inside an argument too, so `cat 'a|b' k` reached nothing.
const ArgSpan = `[\s\S]*`

// PathStart is what may precede a name inside a command line: a separator, a
// quote, or the start of it. Shared with the renderer, so both sides bound a
// name the same way.
const PathStart = `(^|[\s/=:'"])`

// PathStartBound is PathStart without the whitespace, and it exists for the
// binding rule alone. An assignment's value ends at a space, so a subject that
// may open with one reaches past the value into the word after it: with
// PathStart, `msg=hello secrets` is refused for a sentence that names no file.
// Every other rule spans arguments and wants the whitespace.
const PathStartBound = `(^|[/=:'"])`

// Dir is a directory as a subject: the directory itself, or anything under it,
// and nothing that merely begins with its name.
func Dir(dir string) string {
	return regexp.QuoteMeta(dir) + `(?:/|` + PathEnd + `)`
}

// HomeSpellings is the ways a command line names a file under a home: the
// absolute path, and the three prefixes a shell expands to it. A path rule is a
// literal, so `cat ~/.private/x` reaches a file that `cat /home/op/.private/x`
// is refused, and the tilde is how a person and a model both write a home path.
//
// Deliberately not the bare relative spelling. `.private/x` names this file
// only from one directory and names somebody else's from anywhere else, and the
// rule cannot tell which: that breadth is what a name entry is for, where it is
// asked for rather than inferred.
//
// The list is what a shell expands, not every string that could reach the same
// file: a command may build a path a way no rule can enumerate, and this is the
// list that catches an accident rather than the boundary.
func HomeSpellings(home, path string) []string {
	rest, under := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/")
	if home == "" || home == "/" || !under || rest == "" {
		return []string{regexp.QuoteMeta(path)}
	}
	tail := regexp.QuoteMeta("/" + rest)
	return []string{
		regexp.QuoteMeta(path),
		regexp.QuoteMeta("~") + tail,
		regexp.QuoteMeta("$HOME") + tail,
		regexp.QuoteMeta("${HOME}") + tail,
	}
}

// DirUnder is Dir for a path that may sit under a home, bounded the same way
// and matching each spelling of it.
func DirUnder(home, dir string) string {
	spellings := HomeSpellings(home, dir)
	if len(spellings) == 1 {
		return spellings[0] + `(?:/|` + PathEnd + `)`
	}
	return `(?:` + strings.Join(spellings, `|`) + `)(?:/|` + PathEnd + `)`
}

// For is the five rules that refuse a set of subjects: reading one, writing
// one, redirecting output over one, and redirecting one into a command.
//
// Each rule is matched against one command rather than a
// whole line; see Segments, which is what decides where a command ends. The two
// redirect rules match the target word alone, so a heredoc whose body names a
// path is not a redirect over it either way.
//
// The input rule is what the reader vocabulary cannot reach: "< path" hands a
// file to whatever is on the line, and the shell builtins that take it that
// way are words too common to put in a vocabulary matched against every
// command. `while read l; do echo $l; done < key` names no reader and prints
// the file. It is the mirror of the output rule, and disclosure is the
// direction it covers.
//
// A here-string, `<<<"path"`, matches it while passing the text rather than
// the file. That is the limit the whole list has, a rule matching the command
// string and not what it would do, and it errs toward refusing: the answer
// names the rule, and an operator who meant the text writes it another way.
//
// No subjects is no rules rather than a rule matching everything, an empty
// alternation being one that matches the empty string next to any reader.
func For(subjects []string) []string {
	r, ok := fragments(subjects)
	if !ok {
		return nil
	}
	return []string{r.read, r.input, r.write, r.redirect, r.binding}
}

// Disclosing is what puts a subject's contents where they can be read: a reader
// with the path among its arguments, a mover that leaves the contents under a
// name no rule was written for, a file handed to whatever is on the line, and a
// path bound to a variable to be read through later.
//
// What it leaves out is a subject changed where it stands: a writer that only
// alters or removes it, and a redirect over it. That line, rather than the
// read/write one the vocabularies are split on, is what separates the two: a
// brokered command runs as an account of its own and only where an operator
// asked for it, so `chmod` on a declared keyfile or `rm` of one being rotated
// is ordinary work that puts nothing in the conversation, while `mv` of the
// same file into /tmp discloses it one step later.
//
// Everything the agent types is still held to all five rules For builds. The
// asymmetry is the point: nobody asked for what the agent types, and a value it
// cannot read is one it can still destroy, an age key replaced being every
// managed file unreadable retroactively.
func Disclosing(subjects []string) []string {
	r, ok := fragments(subjects)
	if !ok {
		return nil
	}
	return []string{r.read, r.move, r.input, r.binding}
}

// Mentioning is the one rule an entry gets when the operator asks for any
// mention of it to be refused: the subject on its own, with no verb in front.
//
// The other rules exist because naming a file is not the same as reading it,
// and most declared files still have to be managed: a keyfile nothing may
// `chmod` is one nothing may rotate. This is for the file where that trade does
// not apply, a ~/.private and its kind, where the agent has no business naming
// the path for any reason and a refusal is a better answer than a listing.
//
// Opt-in per entry, because it refuses exactly what it says: `ls`, `stat`,
// `test -f`, a `find` that walks past it, and any converge that touches it.
// Nothing infers it from the shape of a path.
func Mentioning(subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	return []string{`(` + strings.Join(subjects, `|`) + `)`}
}

// the five rules, named, so a caller takes the ones it enforces rather than
// slicing a list by position.
type ruleSet struct{ read, move, input, write, redirect, binding string }

// fragments builds the five from one alternation, so they are written once and
// the callers cannot drift. Not ok for no subjects, an empty alternation being
// one that matches the empty string next to any reader.
func fragments(subjects []string) (ruleSet, bool) {
	if len(subjects) == 0 {
		return ruleSet{}, false
	}
	alternation := `(` + strings.Join(subjects, `|`) + `)`
	// The binding rule takes the subjects with the whitespace dropped from
	// what may precede a name; see PathStartBound. A subject that does not
	// open that way is carried through unchanged.
	bound := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		bound = append(bound, strings.Replace(subject, PathStart, PathStartBound, 1))
	}
	boundAlternation := `(` + strings.Join(bound, `|`) + `)`
	return ruleSet{
		read:     ReadCommands + ArgSpan + alternation,
		move:     MoveCommands + ArgSpan + alternation,
		input:    `<\s*\S*` + alternation,
		write:    WriteCommands + ArgSpan + alternation,
		redirect: `>\s*\S*` + alternation,
		binding:  Binding + boundAlternation,
	}, true
}

// NameKind is the shape a declared name takes, inferred from how it is written.
// The shapes differ only in breadth, so reading one as another refuses more or
// fewer files of the same kind; inferring a path from a name is what could turn
// a typo into a rule matching nothing, and nothing here does that.
type NameKind int

const (
	// KindExact is a whole file name, wherever it appears: "age.key".
	KindExact NameKind = iota
	// KindSuffix is a name ending this way: ".key" covers "deploy.key".
	KindSuffix
	// KindPrefix is a name starting this way: ".env" covers ".env.local" but not
	// "faramir.env", which holds refs and is meant to be read.
	KindPrefix
	// KindGlob is a name whose wildcards are not the single leading or trailing
	// one the two kinds above take: "secrets*.yml", and as many as are written.
	KindGlob
	// KindDir is anything below a directory named by the tail of its path:
	// "sops/age/" covers ~/.config/sops/age/keys.txt.
	KindDir
)

// Name is how a declared name is read, and the value with the wildcard or the
// separator that said so taken off. One inference, here, because more than one
// spelling is derived from it -- a regex for the command rules, a glob for each
// agent's own rule file -- and a second copy would be a name that means one
// thing to the guard and another to the agent that typed it.
//
// The order is the order the shapes exclude each other in: a trailing separator
// is a directory whatever else it holds, and a wildcard at one end is an open
// end rather than a name with a hole in it.
func Name(name string) (NameKind, string) {
	switch {
	case strings.HasSuffix(name, "/"):
		return KindDir, name
	case strings.Count(name, "*") == 1 && strings.HasPrefix(name, "*"):
		return KindSuffix, strings.TrimPrefix(name, "*")
	case strings.Count(name, "*") == 1 && strings.HasSuffix(name, "*"):
		return KindPrefix, strings.TrimSuffix(name, "*")
	case strings.Contains(name, "*"):
		return KindGlob, name
	}
	return KindExact, name
}

// NameSubject is a declared name as a fragment of a command line, for the rules
// For and Disclosing build. A command line carries a path inside other text, so
// what anchors it is the reader in front of it rather than the start of a
// string.
func NameSubject(name string) string {
	kind, value := Name(name)
	q := regexp.QuoteMeta(value)
	switch kind {
	case KindSuffix:
		return q + `(` + PathEnd + `)`
	case KindPrefix:
		// No end: a prefix is open by definition, ".env" covering ".env.local".
		return PathStart + q
	case KindGlob:
		return PathStart + strings.ReplaceAll(q, regexp.QuoteMeta("*"), `[^/\s]*`) + `(` + PathEnd + `)`
	case KindDir:
		// The directory itself as well as what is under it. Matching only the form
		// with the separator left `rm -rf ~/.ssh` allowed while `rm -rf ~/.ssh/`
		// was refused, which is a rule a keystroke walks around and a deletion
		// that destroys everything the rule was protecting.
		return PathStart + strings.TrimSuffix(q, `/`) + `(/|` + PathEnd + `)`
	}
	// An exact name may carry separators, so what precedes it is a separator or
	// the start of the word rather than the start of the line.
	return PathStart + q + `(` + PathEnd + `)`
}

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
