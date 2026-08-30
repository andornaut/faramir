package server

import (
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
)

// The brokered half of what this host declares: the [[secret.block]] entries
// and the files [[secret.link]] entries read.
//
// The other half is the agent's own. `faramir init` renders every declared path
// and name into each agent's deny rules and into the guard's pattern file, so
// the agent's file tools and its shell are refused them. Neither reaches a
// brokered command: the guard is a hook over the agent's own tools, and a
// command on the far side of the broker is not one, while the executor holds
// no policy of its own.
// So a declared file was readable through the broker by anything the executor's
// uid could open. That is not a corner: the executor carries the client group so
// a brokered command can work in the enrolled tree, which makes a .env declared
// inside that tree exactly the case that got through.
//
// Blocks and links are held to the same rule here, though what is at stake
// differs. A block promises the value stays out of the conversation and nothing
// else can keep it there: the point of a block is that faramir never reads the
// file, so the redactor holds nothing to cover the output with. A linked file's
// own ref is covered, but a file holds more than the key a link selects, and
// the rest of it is in no redactor either. Both are refused before the command
// runs rather than tokenised after it.
//
// denyrules.Disclosing is the set: reading, moving and re-encoding a declared
// file, and nothing outside that vocabulary, writing over one included. See its comment for where that
// line falls and why it is not the read/write one. An entry carrying strict is
// held to denyrules.Naming instead, which is the subject with no verb in
// front of it: the operator asked for every command naming that file to be
// refused, `ls` and `chmod` with the rest.
type declaredCheck struct{ rules []declaredRule }

// declaredRule is one compiled pattern beside the catalogue entry it came from,
// so a refusal names the entry that matched rather than the set. The two
// listings are where the whole list is readable, which is what makes naming the
// one entry safe.
type declaredRule struct {
	// The catalogue entry, which is what the refusal is written out of: the kind
	// decides which message, and the entry, the ref and the remedy fill it in.
	denyrules.Rule

	re *regexp.Regexp
}

// newDeclaredCheck compiles the catalogue into the rules a brokered command is
// held to. Built once, from the config the daemon started on: an entry changes
// only by a command that re-runs the install, which rewrites config.toml and
// restarts what reads it.
//
// A rule per pattern rather than one alternation over all of them. The guard's
// rendered file packs them, having no message to keep beside one; here the
// entry is the message.
//
// The catalogue itself comes from denyrules.For, which the installer renders
// the guard's file from as well. That is the point of it: a rule reaching one
// tier and not the other used to be a thing that could happen quietly, and the
// commands that act on the install were exactly that.
func newDeclaredCheck(rules []denyrules.Rule) declaredCheck {
	out := make([]declaredRule, 0, len(rules))
	for _, rule := range rules {
		for _, source := range rule.Broker() {
			// Through denyrules, which is where how a rule is read is decided.
			// One inventory read two ways is two inventories again.
			re, err := denyrules.Compile(source)
			// A pattern that will not compile is left out rather than failing the
			// daemon: the loader has already held every entry to its form, so this
			// is unreachable, and a broker that refuses to start refuses every
			// command on the host over one name.
			if err != nil {
				continue
			}
			out = append(out, declaredRule{re: re, Rule: rule})
		}
	}
	return declaredCheck{rules: out}
}

// refuses reports the rule a command would disclose, and whether one did.
//
// The command is matched as a line, which is what the rules are written
// against: a brokered argv is one command, and an argv that hands a string to a
// shell carries a line inside it.
//
// One regular expression per pattern, walked in order. At 170 declared paths
// that is around 520 of them and about 2ms per brokered command, against 0.03ms
// for a single packed alternation over the same subjects. The walk is kept: it
// is what names the entry that matched, and a prefilter in front of it is a
// second thing deciding what is refused, which is the wrong trade on a path
// that already forks a process.
func (d declaredCheck) refuses(cmd []string, cwd string) (declaredRule, bool) {
	if len(d.rules) == 0 || len(cmd) == 0 {
		return declaredRule{}, false
	}
	spellings := declaredSpellings(cmd, cwd)
	for _, rule := range d.rules {
		if slices.ContainsFunc(spellings, rule.re.MatchString) {
			return rule, true
		}
	}
	return declaredRule{}, false
}

// declaredSpellings is every reading of one command the rules are matched
// against.
//
// The line as it was asked for, its paths in their shortest form, and -- the
// reading only the broker can make -- its relative arguments resolved against
// the working directory the request names. The guard has no cwd, so `cd
// /srv/keys && cat luks.key` walks past it there; here the two arrive together
// and the file the command would open is knowable.
//
// An argv is one command and is matched whole. Its words are literal: a ";", a
// "|" or an "&" inside one is an argument the program receives rather than a
// separator, so splitting the joined line on those bytes would put `cat ';'
// /srv/keys/luks.key` past a rule written for the reader in front of the path,
// and would lose an ordinary `sort -t'|' -k2 <path>` by accident.
//
// The string a shell is handed is the one place a command list does arrive, so
// that is what is split per command, as the guard splits one: a reader in the
// first command must not reach a path named in the second.
func declaredSpellings(cmd []string, cwd string) []string {
	words, scripts := shellScripts(cmd)
	out := make([]string, 0, 4+len(scripts)*4)
	out = appendSpelling(out, strings.Join(words, " "))
	if resolved := resolveArgs(words, cwd); resolved != "" {
		out = appendSpelling(out, resolved)
	}
	for _, script := range scripts {
		for _, segment := range denyrules.Segments(script) {
			out = appendSpelling(out, segment)
		}
	}
	return out
}

// appendSpelling adds one reading and its shortest-form twin, where they differ.
func appendSpelling(out []string, spelling string) []string {
	if spelling == "" {
		return out
	}
	out = append(out, spelling)
	if cleaned := denyrules.NormalizePaths(spelling); cleaned != spelling {
		out = append(out, cleaned)
	}
	return out
}

// shells whose -c argument is a command line rather than a file to run.
var shellNames = map[string]bool{
	"sh": true, "bash": true, "dash": true, "ash": true, "zsh": true, "ksh": true,
}

// shellScripts separates an argv's own words from the command lines it hands a
// shell, so each is read as what it is.
//
// Scanned across the whole argv rather than at argv[0] alone: `sudo sh -c ...`
// and `env FOO=1 bash -c ...` are the same handoff one word later, and a model
// writes both. A -c before any shell is some other program's flag and is left
// among the words.
func shellScripts(cmd []string) (words, scripts []string) {
	words = make([]string, 0, len(cmd))
	var shell bool
	for i := 0; i < len(cmd); i++ {
		word := cmd[i]
		if shellNames[filepath.Base(word)] {
			shell = true
		}
		if shell && word == "-c" && i+1 < len(cmd) {
			words = append(words, word)
			scripts = append(scripts, cmd[i+1])
			i++
			continue
		}
		words = append(words, word)
	}
	return words, scripts
}

// resolveArgs is the command with every relative argument spelled from the
// root, or "" where that changes nothing.
//
// Arguments only: argv[0] is the program, and the rules read it as the verb in
// front of the path rather than as a path of its own. A word carrying
// whitespace is left alone, being a string handed to a shell rather than one
// filename, and joining a directory onto it would invent a path nobody wrote. A
// flag is left alone for the same reason.
func resolveArgs(cmd []string, cwd string) string {
	if len(cmd) == 0 || !filepath.IsAbs(cwd) {
		return ""
	}
	out := make([]string, len(cmd))
	out[0] = cmd[0]
	changed := false
	for i, arg := range cmd[1:] {
		out[i+1] = arg
		if arg == "" || filepath.IsAbs(arg) || strings.HasPrefix(arg, "-") ||
			strings.ContainsAny(arg, " \t\n") {
			continue
		}
		out[i+1] = filepath.Join(cwd, arg)
		changed = true
	}
	if !changed {
		return ""
	}
	return strings.Join(out, " ")
}

// a refusal is what a caller is told, in the parts every one of them has:
// what matched and why no other answer is available, then what to do instead,
// and for a path the sentence saying what the entry leaves alone.
//
// Parts rather than one string, because the remedy is the half a reader can
// act on and a message that lost it still read as a whole sentence. Asserting
// prose means listing the phrases somebody thought of; asserting a field means
// asking whether the message has a remedy at all.
type refusal struct {
	// body is what was refused and why this route cannot answer.
	body string
	// remedy is what to do instead. Never empty: a refusal with nothing to
	// offer sends its reader looking for a way round it.
	remedy string
	// tail says what the entry leaves alone, and is for the path kinds. The
	// others have no vocabulary to describe.
	tail string
}

func (r refusal) text() string {
	out := r.body + "\n\n" + r.remedy
	if r.tail != "" {
		out += " " + r.tail
	}
	return out
}

// declaredRefusal is what the caller is told, which reaches a model rather than
// the operator: it names the entry that matched, says why no other answer is
// available, and leaves the remedy where it belongs.
func declaredRefusal(rule declaredRule) string {
	return refusalFor(rule).text()
}

// refusalFor is the message per kind, and the kinds come from the catalogue
// both tiers are built from. The switch carries no default, so a kind added
// there is a lint error here rather than a rule answered with the wrong
// sentence: a command entry told what a reader may still do to a file is what
// that used to look like.
func refusalFor(rule declaredRule) refusal {
	switch rule.Kind {
	case denyrules.KindOwn:
		return refusal{
			body: "this is " + rule.Entry + ", which is faramir's own, so a brokered " +
				"command may not name it whatever it would do with it. There is no entry " +
				"to remove: these are rendered from the install's layout on every run, " +
				"and this side runs as an account of its own, or as root where an " +
				"escalation was approved, so a mode is no answer here.",
			remedy: "If this is deliberate, it is the operator's to do, outside faramir.",
		}
	case denyrules.KindOperator:
		return refusal{
			body: "this command acts on the faramir install rather than through it, so " +
				"it is the operator's to run and this route is no way round that: a " +
				"brokered command runs as an account with less reach than you, not " +
				"more.",
			remedy: "Ask the operator. Where `faramir doctor` says to run it as " +
				"root for the rest of an answer, that line is addressed to them.",
		}
	case denyrules.KindOwnAction:
		return refusal{
			body: "this is faramir's own binary, one of the files an enrolment " +
				"installs, or one of its units. Refused not because it would disclose " +
				"anything but because it would change or stop what keeps credentials out " +
				"of this conversation, and a brokered command has less reach than you " +
				"rather than more.",
			remedy: "If this is deliberate, it is the operator's to do.",
		}
	case denyrules.KindCommand:
		// No tail: it is about what a reader may still do to a file, and names
		// nothing somebody who ran `op read` typed.
		return refusal{
			body: rule.Kind.List() + " on this host name the command " + rule.Entry +
				", so no brokered command may run it. The words are matched where a " +
				"command starts, so the same words inside an argument or a path are " +
				"left alone; a line of a heredoc is read as a command and is not.",
			remedy: "If the work needs it, that is the operator's, either " +
				"outside faramir or after " + rule.Remedy + ".",
		}
	case denyrules.KindBlocked, denyrules.KindLinked:
		// Below, both kinds sharing one message: they differ in the listing they
		// name and the removal they offer, which the rule carries.
	}
	// What the entry leaves alone, which is the sentence that tells a reader
	// whether another spelling is worth trying. A strict entry leaves nothing
	// alone, and saying otherwise sends a model back for the same `ls`.
	tail := "What is refused is a vocabulary rather than a direction: the " +
		"readers, wherever the path appears in the line, so `cp`, `tee` and " +
		"`sed` are refused even where that path is what they write to. " +
		"A command outside it is not refused, whatever it does to the file: " +
		"`chmod`, `rm` and `mv` among them."
	if rule.Strict {
		tail = "Changing it where it stands is refused with the rest, which is " +
			"what this entry asks for: no command may name it."
	}
	// Only the two path kinds reach here, and both are an entry: they have a
	// listing to name and a removal to offer, so neither is asked for.
	return refusal{
		body: rule.Kind.List() + " on this host name " + declaredSubject(rule) +
			", and a brokered command may not print what they name. " +
			"Its contents are covered by nothing on the way back: a file named there " +
			"is one faramir either never reads or reads a single ref out of, so there " +
			"is no value to replace in this command's output.",
		remedy: "Reading it is the operator's, either outside faramir or after " +
			rule.Remedy + ".",
		tail: tail,
	}
}

// declaredSubject is how the refusal names a path entry: the file, the ref it
// answers where a link is what named it, and the stricter entry saying so
// itself. A command refused for naming a path it never read is one whose author
// would otherwise reach for a way round it, so the sentence has to carry why.
func declaredSubject(rule declaredRule) string {
	what := "the path " + rule.Entry
	if rule.Ref != "" {
		// What a caller is meant to do with a linked credential is ask for it by
		// name, and the refusal is where to say so.
		what = "the file " + rule.Entry + ", which answers " + rule.Ref
	}
	if rule.Strict {
		what += ", which no command may name at all"
	}
	return what
}

// agentHomeDir is the home a "~" in a command stands for. The agent runs as the
// operator, so it is that account's, and "" wherever it cannot be resolved,
// which leaves the rules matching the spellings that need no home.
func agentHomeDir(name string) string {
	if name == "" {
		return ""
	}
	account, err := user.Lookup(name)
	if err != nil || account.HomeDir == "" || account.HomeDir == "/" {
		return ""
	}
	return account.HomeDir
}
