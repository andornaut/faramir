package denyrules

// The spellings of a path a rule has to refuse: cleaned, relative to the home,
// under a prefix, or as a glob.

import (
	"path"
	"regexp"
	"strings"
)

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
// The bare relative spelling as well, which the four prefixed forms all miss: a
// command that changes directory first names the file with no prefix at all, so
// `cd $HOME && cat .private/x` reaches what `cat ~/.private/x` is refused. A
// rule matched against one command's text cannot follow a working directory, so
// it matches the tail wherever the tail appears, and a file of the same name in
// another tree is refused with it. That is a refusal and not a disclosure.
//
// That one carries pathStart, unlike the four above it. They open on a `/` or a
// prefix that cannot sit inside a word; a bare `.npmrc` would otherwise match
// the tail of `package.npmrc`, which is a different file. A slash is left in
// the class, the tail under another root being the cost this spelling accepts.
//
// And it is written only for a tail that is a path rather than a word: one with
// a `/` in it, or a name opening on a dot. pathStart stops a match inside a word
// and not a match on a whole one, so a rule for ~/secrets would otherwise refuse
// `echo "no secrets here"` and every command naming any /secrets/ anywhere on
// the host. globUnder declines a rule at the same boundary and for the same
// reason. What that gives up is a tail that is neither: `cd $HOME && cat notes`
// is not refused, and a path directly under a home wants a name of its own.
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
	out := []string{
		quotePath(path),
		regexp.QuoteMeta("~") + tail,
		regexp.QuoteMeta("$HOME") + tail,
		regexp.QuoteMeta("${HOME}") + tail,
	}
	if strings.Contains(rest, "/") || strings.HasPrefix(rest, ".") {
		out = append(out, pathStart+quotePath(rest))
	}
	return out
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

// TrailingPrefix splits an entry written as a trailing-wildcard prefix into the
// literal a name has to start with, and reports whether it is one. The loader
// accepts that form only with a literal character before the "*" and no other
// wildcard anywhere, so a caller here can take the split at face value.
//
// The one place the form is recognised, so the two subject builders below and
// anything that grows beside them read it the same way.
func TrailingPrefix(path string) (string, bool) {
	literal, ok := strings.CutSuffix(path, "*")
	if !ok || literal == "" || strings.HasSuffix(literal, "/") {
		return path, false
	}
	return literal, true
}

// nameRest is what may follow a prefix inside the component it names: the rest
// of that name, up to the separator that ends it or the end of the word.
//
// A class rather than ".*", which would cross a "/" and make a rule for
// <dir>/ssfn* refuse <dir>/ssfnx/../other. The name a prefix stands for is one
// component, so the rule stops where the component does. pathEnd's characters
// are excluded for the same reason it bounds a literal: a name ends at a quote
// or a separator as surely as at a space.
const nameRest = `[^\s"';&|)/]*`

// DirUnder is Dir for a path that may sit under a home, bounded the same way
// and matching each spelling of it.
//
// An entry written as a trailing-wildcard prefix is the same rule with the last
// component left open: the literal is matched as written and the rest of that
// name is whatever the file is actually called. So an entry for <dir>/ssfn*
// refuses <dir>/ssfn682576826927347580 without this config ever carrying that
// number, and refuses <dir>/ssfn* typed as a pattern with it.
//
// The bound after it is the literal's: a name may end there, or carry on into a
// path below it, which is what covers a prefix standing for a directory.
func DirUnder(home, dir string) string {
	tail := `(?:/|` + pathEnd + `)`
	if literal, isPrefix := TrailingPrefix(dir); isPrefix {
		dir = literal
		tail = nameRest + tail
	}
	spellings := homeSpellings(home, dir)
	if len(spellings) == 1 {
		return spellings[0] + tail
	}
	return `(?:` + strings.Join(spellings, `|`) + `)` + tail
}

// globUnder refuses a shell glob that could expand to path, and is "" where
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
func globUnder(home, path string) string {
	// A prefix entry knows the start of the name and not the end of it, so the
	// suffix half below has nothing to constrain: any pattern whose literal
	// opening is a prefix of the declared one could expand to a name that starts
	// with it, whatever follows. openSuffix says so, and the prefixes are taken
	// from the literal exactly as they are for a name written in full.
	//
	// Wider than the rule for a literal, and bounded by the same directory: a
	// pattern is refused only where it sits under the parent the entry named.
	literal, isPrefix := TrailingPrefix(path)
	trimmed := strings.TrimSuffix(literal, "/")
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
	//
	// A prefix entry is held to the same bound by the literal it opens on, not by
	// the whole of it: "/home/o*" is not "/home/op" by the element comparison
	// below and its parent is /home, so the rule it would render refuses
	// `cat /home/*` for every account -- the thing this exists to prevent, reached
	// by an entry one character short of the home's own name.
	if cleanHome := strings.TrimSuffix(home, "/"); cleanHome != "" {
		if strings.HasPrefix(cleanHome+"/", trimmed+"/") {
			return ""
		}
		if isPrefix && strings.HasPrefix(cleanHome, trimmed) {
			return ""
		}
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
	// quotePath rather than QuoteMeta, as the directory half uses: a name holding
	// a space is written `Local\ Storage` as often as it is quoted, and a glob
	// rule that took only the quoted spelling would leave the escaped one open on
	// exactly the entries the space handling was written for.
	parts := func() []string {
		out := make([]string, 0, len(name)+1)
		for n := len(name); n >= 0; n-- {
			out = append(out, quotePath(name[:n]))
		}
		return out
	}()
	suffixes := make([]string, 0, len(name)+1)
	if isPrefix {
		// The end of the name is not declared, so nothing here may constrain it.
		suffixes = append(suffixes, nameRest)
	} else {
		for n := 0; n <= len(name); n++ {
			suffixes = append(suffixes, quotePath(name[n:]))
		}
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
//
// The bare tail is kept here as well as in DirUnder, and it is the expensive
// one: globUnder builds its prefix from this and multiplies it against a
// per-character alternation, which is most of what the tail costs both tiers.
// What it buys is `cd $HOME && cat <dir>/*`, a glob after a change of
// directory, which is the shape an agent enumerating a directory writes. The
// trade was measured and taken.
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
