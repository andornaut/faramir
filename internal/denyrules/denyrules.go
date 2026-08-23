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
	if len(subjects) == 0 {
		return nil
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
	return []string{
		ReadCommands + ArgSpan + alternation,
		`<\s*\S*` + alternation,
		WriteCommands + ArgSpan + alternation,
		`>\s*\S*` + alternation,
		Binding + boundAlternation,
	}
}
