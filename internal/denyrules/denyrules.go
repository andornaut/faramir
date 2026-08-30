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
		`strings|base64|base32|hexdump|uuencode|rev|tac|awk|cut|nl|dd|jq|yq|sed|` +
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
// stops. The class matches pathEnd's, so what counts as the end of a path is
// one answer rather than two.
var pathWord = regexp.MustCompile(`[^\s"';&|()]*/[^\s"';&|()]*`)

// binding is a path bound to a shell variable, by an assignment or by the list
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
// What keeps the quoted form from reaching prose is pathStartBound rather than
// anything here: a name may not open after a space, so a sentence that says one
// is left alone while a path anywhere inside the quotes is not.
//
// A for list runs to the end of the command, so it stops at a separator.
//
// An assignment opens a word, which is what assignStart states and what a "\b"
// could not: a boundary falls after a hyphen too, so `--key-file=/srv/keys/luks.key`
// matched at "file=" and a flag was refused as though it bound a variable. The
// separators and the quotes are there because an assignment follows each of
// them, and the hyphen is the one thing that has to be left out.
const binding = `(?:` + assignStart + `[A-Za-z_][A-Za-z0-9_]*=(?:["'][^"']*|\S*)` +
	`|\bfor\s+[A-Za-z_][A-Za-z0-9_]*\s+in\s+[^;&|]*)`

// assignStart is where a shell word may begin: the start of the line, or after
// whitespace, a separator or a quote.
const assignStart = `(?:^|[\s;&|("'])`

// pathEnd is what may follow a path in a command line: whitespace, a quote, a
// separator, or the end of it. A class rather than \b, and shared so the two
// sides bound a path the same way: "\b" holds beside a hyphen, so a rule for
// /opt/faramir would match /opt/faramir-notes.md and refuse a sibling that
// merely starts the same way.
const pathEnd = `[\s"';&|)]|$`

// ArgSpan is what a rule crosses between a command and a path it reaches: the
// arguments in between.
//
// Everything, because a rule is matched against one command rather than against
// a whole line: Segments is what decides where a command ends, and it reads the
// quoting a pattern cannot. A class that stopped at a pipe would stop at one
// inside an argument too, so `cat 'a|b' k` reached nothing.
const ArgSpan = `[\s\S]*`

// pathStart is what may precede a name inside a command line: a separator, a
// quote, or the start of it.
const pathStart = `(^|[\s/=:'"])`

// pathStartBound is pathStart without the whitespace, and it exists for the
// binding rule alone. An assignment's value ends at a space, so a subject that
// may open with one reaches past the value into the word after it: with
// pathStart, `msg=hello secrets` is refused for a sentence that names no file.
// Every other rule spans arguments and wants the whitespace.
const pathStartBound = `(^|[/=:'"])`

// Dir is a directory as a subject: the directory itself, or anything under it,
// and nothing that merely begins with its name.
func Dir(dir string) string {
	return regexp.QuoteMeta(dir) + `(?:/|` + pathEnd + `)`
}

// homeSpellings is the ways a command line names a file under a home: the
// absolute path, and the three prefixes a shell expands to it. A path rule is a
// literal, so `cat ~/.private/x` reaches a file that `cat /home/op/.private/x`
// is refused, and the tilde is how a person and a model both write a home path.
//
// Deliberately not the bare relative spelling. `.private/x` names this file
// only from one directory and names somebody else's from anywhere else, and the
// rule cannot tell which. Refusing it everywhere would refuse the file of that
// name in every tree on the host, which is not what the entry asked for.
//
// The list is what a shell expands, not every string that could reach the same
// file: a command may build a path a way no rule can enumerate, and this is the
// list that catches an accident rather than the boundary.
func homeSpellings(home, path string) []string {
	rest, under := strings.CutPrefix(path, strings.TrimSuffix(home, "/")+"/")
	if home == "" || home == "/" || !under || rest == "" {
		return []string{quotePath(path)}
	}
	tail := quotePath("/" + rest)
	return []string{
		quotePath(path),
		regexp.QuoteMeta("~") + tail,
		regexp.QuoteMeta("$HOME") + tail,
		regexp.QuoteMeta("${HOME}") + tail,
	}
}

// quotePath is QuoteMeta plus the one thing a shell writes two ways: a space in
// a path is a space inside quotes and a backslash-space outside them, and both
// reach the same file. QuoteMeta leaves a space alone, so a subject built from
// it carries the quoted spelling and misses `cat ~/dir/Local\ Storage`.
//
// Only the space. A shell will accept `L\ocal` and `"Local Storage"` spelled a
// dozen other ways, and a rule cannot be a shell; what this covers is the
// spelling a person or a model actually writes for a name that has a space in
// it, which an Electron profile has several of.
func quotePath(path string) string {
	return strings.ReplaceAll(regexp.QuoteMeta(path), " ", `(?: |\\ )`)
}

// DirUnder is Dir for a path that may sit under a home, bounded the same way
// and matching each spelling of it.
func DirUnder(home, dir string) string {
	spellings := homeSpellings(home, dir)
	if len(spellings) == 1 {
		return spellings[0] + `(?:/|` + pathEnd + `)`
	}
	return `(?:` + strings.Join(spellings, `|`) + `)(?:/|` + pathEnd + `)`
}

// GlobUnder refuses a shell glob that could expand to path, and is "" where
// there is nothing to write.
//
// It exists because a declared file and a declared directory fail differently
// against a pattern. A directory's subject is a prefix of everything under it,
// so `cat <dir>/*` matches it as written. A file's subject is the file's own
// name, and a glob carries no name: the shell expands it after the guard has
// answered, so `cat <dir>/*` reaches a declared file that `cat <dir>/<file>` is
// refused.
//
// What it matches is the path with its last component replaced by a pattern that
// could still produce that component: a prefix of the name, a wildcard, then a
// suffix of it. So a rule for ~/.ssh/id_rsa refuses `~/.ssh/*` and `~/.ssh/id_r*`
// and leaves `~/.ssh/known_*` alone, which no rule about the directory could do,
// and a rule for a project's .env leaves `ls *.md` alone, which matching the
// prefix alone did not. Nothing here expands a pattern or asks the filesystem
// anything; both halves come from the declared name.
//
// This is why the rule needs no answer to "is the entry a file": for a declared
// directory it refuses the patterns that would name that directory, which the
// directory's own subject already covers.
//
// What it does not reach: a wildcard higher up the path (`~/.s*/id_rsa`), a
// character class standing in for a literal (`~/.ssh/id_[r]sa`), a second
// wildcard in the trailing half (`id_*s*`), and any path a command builds at run
// time. Those are the limits the rules already have, and
// this is the list that catches an accident.
func GlobUnder(home, path string) string {
	trimmed := strings.TrimSuffix(path, "/")
	i := strings.LastIndex(trimmed, "/")
	if i <= 0 {
		return ""
	}
	dir, name := trimmed[:i], trimmed[i+1:]
	if name == "" || dir == "" || dir == "/" {
		return ""
	}
	// A home, or anything above one, gets no rule. The parent of a home is
	// /home, and a pattern rule there answers for every account on the host.
	if cleanHome := strings.TrimSuffix(home, "/"); cleanHome != "" &&
		strings.HasPrefix(cleanHome+"/", trimmed+"/") {
		return ""
	}
	// What a pattern that could produce this name looks like: a prefix of it, a
	// wildcard, then a suffix of it, and then the end of the word.
	//
	// Both halves, not just the prefix. Matching the prefix alone and stopping
	// at the wildcard makes every pattern match on the empty prefix, so one
	// declared .env in a project refuses `ls *.md` and `git add *` with it. The
	// trailing literal is what tells `*` from `*.md`: the first could expand to
	// the name and the second could not.
	//
	// The empty prefix and the empty suffix are both included, which is what
	// keeps a bare `*` refused. That one is deliberately broad: a shell expands
	// it to a dotfile only where it is set to, and this cannot know, so it
	// refuses the pattern that might.
	//
	// Longest first, which is how a reader checks them.
	parts := func() []string {
		out := make([]string, 0, len(name)+1)
		for n := len(name); n >= 0; n-- {
			out = append(out, regexp.QuoteMeta(name[:n]))
		}
		return out
	}()
	suffixes := make([]string, 0, len(name)+1)
	for n := 0; n <= len(name); n++ {
		suffixes = append(suffixes, regexp.QuoteMeta(name[n:]))
	}
	pattern := `/(?:` + strings.Join(parts, `|`) + `)` + globChar +
		`(?:` + strings.Join(suffixes, `|`) + `)(?:` + pathEnd + `)`
	spellings := dirSpellings(home, dir)
	if len(spellings) == 1 {
		return spellings[0] + pattern
	}
	return `(?:` + strings.Join(spellings, `|`) + `)` + pattern
}

// dirSpellings is homeSpellings for a directory, which has one case that one
// does not: the home itself. homeSpellings works on a path under a home and
// returns the literal alone for the home, so a file directly in a home would
// lose the `~` spelling that is how a person and a model both write it.
func dirSpellings(home, dir string) []string {
	if cleanHome := strings.TrimSuffix(home, "/"); cleanHome != "" && dir == cleanHome {
		return []string{
			regexp.QuoteMeta(dir),
			regexp.QuoteMeta("~"),
			regexp.QuoteMeta("$HOME"),
			regexp.QuoteMeta("${HOME}"),
		}
	}
	return homeSpellings(home, dir)
}

// globChar is what makes a word a pattern rather than a name. A shell expands
// these before the command runs, so a rule matched against the text has to
// answer the pattern.
const globChar = `[*?\[]`

// Naming is the rule the guard applies: a subject named at all is refused.
//
// No verb in front of it, and that is the whole of the change from what the
// broker uses. A subject is an absolute path, and an absolute path in a command
// line is a reference to that file: nothing says /etc/faramir/age.key in
// passing. A verb list was needed while a subject could be a bare name, where
// "credentials" appears in a sentence as readily as in a command; it cannot be
// needed for a path.
//
// The list it replaces failed open, which is the reason to be rid of it here. A
// command absent from a reader vocabulary read a declared file unrefused, so
// that list reached fifty words and was still short of rg, fd and bat. A rule
// about the path has nothing to be short of.
//
// What it costs is prose and metadata: a sentence quoting a declared path is
// refused, and so is `ls` on one. Both are refusals rather than disclosures, and
// the agent has the brokered route for the second.
//
// Not anchored on the left, deliberately. A rule for /etc/faramir also refuses
// /srv/backup/etc/faramir/age.key, a copy of the protected tree under another
// root, which is worth refusing. pathEnd bounds the right, so
// /etc/faramir-notes.md is not part of /etc/faramir.
//
// Both tiers use it. For the guard it is the whole rule; for the broker it is
// what a `strict` entry gets instead of Disclosing, the operator having asked
// that no brokered command name the path for any reason, `ls` and `chmod` with
// the rest.
//
// No subjects is no rules rather than a rule matching everything, an empty
// alternation being one that matches the empty string.
func Naming(subjects []string) []string {
	return subjectRule("", subjects)
}

// subjectRule is the one place a subject rule is spelled, named or not, so the
// syntax NamingAs writes is the syntax KindMarker looks for.
func subjectRule(kind string, subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	open := `(`
	if kind != "" {
		open = KindMarker(kind)
	}
	return []string{open + strings.Join(subjects, `|`) + `)`}
}

// Kinds of subject, as NamingAs writes them into a rule and adviceFor reads
// them back out. The strings are part of the rendered file and of the compiled
// fallback, so they are as fixed as any pattern here.
const (
	// KindBlocked is a path a [[secret.block]] entry names.
	KindBlocked = "blocked"
	// KindLinked is the file a [[secret.link]] entry reads.
	KindLinked = "linked"
	// KindOwn is a directory this install occupies, which no entry declares and
	// no removal takes back.
	KindOwn = "own"
)

// NamingAs is Naming with the kind of entry written into the rule as a named
// group.
//
// The group matches exactly what the rule matched and changes nothing about
// what is refused. What it is for is the refusal: one rule over every declared
// path cannot otherwise say whether the path was blocked, linked, or is the
// install's own, so the message could not name the command that takes it back
// and had to offer two and a way to tell them apart.
//
// A group rather than a second list beside the patterns, because the rendered
// file is a list of patterns and nothing else, and a label kept alongside would
// be a second thing for an install to get out of step.
func NamingAs(kind string, subjects []string) []string {
	return subjectRule(kind, subjects)
}

// KindMarker is what a rule of that kind opens with, for a reader that has the
// rule as text rather than as a compiled regexp. The guard's shipped file is a
// list of patterns and its refusal picks a message by what the pattern says, so
// the marker is written once here rather than spelled again there.
func KindMarker(kind string) string {
	return `(?P<` + kind + `>`
}

// Disclosing is the rule the broker applies, and the one place a verb list is
// still the right answer.
//
// The guard refuses a declared path outright: see Naming. This side cannot,
// because using a credential file is what a brokered command is for. `cryptsetup
// luksOpen --key-file <path>`, `ssh -i <path>` and `git -c
// core.sshCommand=... ` all name a declared path and disclose nothing, and the
// set of programs that read a credential without printing it is not one anybody
// can finish writing.
//
// So this list fails open on purpose, and that is safe here in a way it was not
// there. A verb missing from it costs the operator a command of their own that
// went through; a verb missing from the guard's list cost them the file. The
// account on this side is running what the operator asked for.
//
// What it covers: a reader with the path among its arguments, a file handed to
// whatever is on the line, and a path bound to a variable to be read through
// later. A reader whatever it is called, `sed -n p` printing a file as surely
// as `cat` does.
//
// What it leaves out is everything else done to the file: a writer that alters
// or removes it, a redirect over it, and a move or a link that puts it under
// another name. That line, rather than the read/write one the guard is split
// on, is what separates the two: `chmod` on a declared keyfile, `rm` of one
// being rotated and `mv` of one into place are ordinary work that puts nothing
// in the conversation, and refusing them takes out the converge that rotates a
// key.
//
// What it costs, stated plainly rather than argued away. `faramir run` is the
// agent's to invoke, not the operator's: only an escalation is approved per
// command. So a brokered `mv` or `ln -s` of a declared file to a path no rule
// names, followed by a read of that path with the agent's own file tools, is a
// disclosure this tier does not stop. It is the move-then-read the vocabulary
// once carried a rule against. That rule is gone because it also refused the
// rotation, and `--strict` is the per-entry answer where an entry would rather
// have the refusal than the converge.
//
// Everything the agent types is still held to Naming. The
// asymmetry is the point: nobody asked for what the agent types, and a value it
// cannot read is one it can still destroy, an age key replaced being every
// managed file unreadable retroactively.
func Disclosing(subjects []string) []string {
	r, ok := fragments(subjects)
	if !ok {
		return nil
	}
	return []string{r.read, r.input, r.binding}
}

// the rules, named, so a caller takes the ones it enforces rather than
// slicing a list by position.
type ruleSet struct{ read, input, binding string }

// fragments builds them from one alternation, so they are written once and
// the callers cannot drift. Not ok for no subjects, an empty alternation being
// one that matches the empty string next to any reader.
func fragments(subjects []string) (ruleSet, bool) {
	if len(subjects) == 0 {
		return ruleSet{}, false
	}
	alternation := `(` + strings.Join(subjects, `|`) + `)`
	// The binding rule takes the subjects with the whitespace dropped from
	// what may precede a name; see pathStartBound. A subject that does not
	// open that way is carried through unchanged.
	bound := make([]string, 0, len(subjects))
	for _, subject := range subjects {
		bound = append(bound, strings.Replace(subject, pathStart, pathStartBound, 1))
	}
	boundAlternation := `(` + strings.Join(bound, `|`) + `)`
	return ruleSet{
		read:    ReadCommands + ArgSpan + alternation,
		input:   `<\s*\S*` + alternation,
		binding: binding + boundAlternation,
	}, true
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
