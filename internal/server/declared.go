package server

import (
	"os/user"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
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
// held to denyrules.Mentioning instead, which is the subject with no verb in
// front of it: the operator asked for every command naming that file to be
// refused, `ls` and `chmod` with the rest.
type declaredCheck struct{ rules []declaredRule }

// declaredRule is one compiled pattern and what it was built from, so a refusal
// names the entry that matched rather than the set. `faramir block ls` and
// `faramir link ls` are where the whole list is readable, which is what makes
// naming the one entry safe.
type declaredRule struct {
	re *regexp.Regexp
	// what the operator declared, as the refusal says it.
	what string
	// remedy is the command that takes the entry back out.
	remedy string
	// strict is the entry the operator asked to have refused wherever it is
	// named. The refusal has to say so: the sentence a looser entry ends on tells
	// the reader that changing the file is left alone, which for this one is the
	// opposite of what just happened.
	strict bool
}

// newDeclaredCheck compiles what this host declares. Built once, from the
// config the daemon started on: `faramir block add` and `faramir link add`
// re-run the install, which rewrites config.toml and restarts what reads it.
//
// A rule per entry rather than one alternation over all of them. The rendered
// pattern file packs them, having no message to write; here the entry is the
// message.
//
// agentHome is the home a "~" stands for, empty where it cannot be resolved. A
// brokered command's argv carries no shell expansion, but its `sh -c` string
// does, and that is the spelling a model writes.
func newDeclaredCheck(secret config.SecretConfig, agentHome string) declaredCheck {
	var out []declaredRule
	add := func(what, remedy string, strict bool, sources []string) {
		for _, source := range sources {
			re, err := regexp.Compile(source)
			// A pattern that will not compile is left out rather than failing the
			// daemon: the loader has already held every entry to its form, so this
			// is unreachable, and a broker that refuses to start refuses every
			// command on the host over one declared name.
			if err != nil {
				continue
			}
			out = append(out, declaredRule{
				re: re, what: what, remedy: remedy, strict: strict,
			})
		}
	}
	// how an entry's subject is matched: every command naming it where the
	// operator asked for that, and the disclosing ones otherwise.
	rulesFor := func(subject string, strict bool) []string {
		if strict {
			return denyrules.Mentioning([]string{subject})
		}
		return denyrules.Disclosing([]string{subject})
	}
	for _, entry := range secret.Blocked {
		const remedy = "`faramir block rm`"
		switch {
		case entry.Command != "":
			// A command entry is already about what a command does, so it is matched
			// as itself rather than as a subject for the rules above. The loader
			// refuses strict on one, there being no looser reading to tighten.
			if rule := denyrules.CommandRule(entry.Command); rule != "" {
				add("the command "+entry.Command, remedy, false, []string{rule})
			}
		case entry.Path != "":
			add(named("the path "+entry.Path, entry.Strict), remedy, entry.Strict,
				rulesFor(denyrules.DirUnder(agentHome, entry.Path), entry.Strict))
		}
	}
	for _, link := range secret.Links {
		if link.Path == "" {
			continue
		}
		// The ref as well as the file: what a caller is meant to do with a linked
		// credential is ask for it by name, and the refusal is where to say so.
		add(named("the linked file "+link.Path+", which answers "+link.Ref, link.Strict),
			"`faramir link rm`", link.Strict,
			rulesFor(denyrules.DirUnder(agentHome, link.Path), link.Strict))
	}
	return declaredCheck{rules: out}
}

// named is how the refusal says what matched, with the stricter entry saying so
// itself. A command refused for naming a path it never read is one whose author
// would otherwise reach for a way round it: the sentence has to carry why.
func named(what string, strict bool) string {
	if strict {
		return what + ", which no command may name at all,"
	}
	return what
}

// refuses reports the rule a command would disclose, and whether one did.
//
// The command is matched as a line, which is what the rules are written
// against: a brokered argv is one command, and an argv that hands a string to a
// shell carries a line inside it.
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

// declaredRefusal is what the caller is told, which reaches a model rather than
// the operator: it names the entry that matched, says why no other answer is
// available, and leaves the remedy where it belongs.
func declaredRefusal(rule declaredRule) string {
	// What the entry leaves alone, which is the sentence that tells a reader
	// whether another spelling is worth trying. An strict entry leaves
	// nothing alone, and saying otherwise sends a model back for the same `ls`.
	tail := "What is refused is a vocabulary rather than a direction: the " +
		"readers, and the commands that move or re-encode a file, wherever the " +
		"path appears in the line, so `cp`, `tee` and `sed` are refused even " +
		"where it is what they write to. A command outside it is not refused, " +
		"whatever it does to the file."
	if rule.strict {
		tail = "Changing it where it stands is refused with the rest, which is " +
			"what this entry asks for: no command may name it."
	}
	return "this host declares " + rule.what +
		" and a brokered command may not read, copy or move what is declared. " +
		"Its contents are covered by nothing on the way back: a declared file is " +
		"one faramir either never reads or reads a single ref out of, so there is " +
		"no value to replace in this command's output.\n\n" +
		"Reading it is the operator's, either outside faramir or after " +
		rule.remedy + ". " + tail
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
