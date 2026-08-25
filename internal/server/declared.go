package server

import (
	"os/user"
	"path/filepath"
	"regexp"
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
// brokered command: the guard is a hook over shell tools, and an MCP
// faramir_run call is not one, while the executor holds no policy of its own.
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
// file, not changing one where it stands. See its comment for where that line
// falls and why it is not the read/write one.
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
	add := func(what, remedy string, sources []string) {
		for _, source := range sources {
			re, err := regexp.Compile(source)
			// A pattern that will not compile is left out rather than failing the
			// daemon: the loader has already held every entry to its form, so this
			// is unreachable, and a broker that refuses to start refuses every
			// command on the host over one declared name.
			if err != nil {
				continue
			}
			out = append(out, declaredRule{re: re, what: what, remedy: remedy})
		}
	}
	for _, entry := range secret.Blocked {
		const remedy = "`faramir block rm`"
		switch {
		case entry.Command != "":
			// A command entry is already about what a command does, so it is matched
			// as itself rather than as a subject for the rules above.
			if rule := denyrules.CommandRule(entry.Command); rule != "" {
				add("the command "+entry.Command, remedy, []string{rule})
			}
		case entry.Name != "":
			add("the name "+entry.Name, remedy,
				denyrules.Disclosing([]string{denyrules.NameSubject(entry.Name)}))
		case entry.Path != "":
			add("the path "+entry.Path, remedy,
				denyrules.Disclosing([]string{denyrules.DirUnder(agentHome, entry.Path)}))
		}
	}
	for _, link := range secret.Links {
		if link.Path == "" {
			continue
		}
		// The ref as well as the file: what a caller is meant to do with a linked
		// credential is ask for it by name, and the refusal is where to say so.
		add("the linked file "+link.Path+", which answers "+link.Ref,
			"`faramir link rm`",
			denyrules.Disclosing([]string{denyrules.DirUnder(agentHome, link.Path)}))
	}
	return declaredCheck{rules: out}
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
		for _, spelling := range spellings {
			if rule.re.MatchString(spelling) {
				return rule, true
			}
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
// Split per command first, as the guard does: a pattern matched against a whole
// line cannot tell one command from the next, so a reader in the first would
// reach a path named in the second.
func declaredSpellings(cmd []string, cwd string) []string {
	lines := []string{strings.Join(cmd, " ")}
	if resolved := resolveArgs(cmd, cwd); resolved != "" {
		lines = append(lines, resolved)
	}
	out := make([]string, 0, len(lines)*4)
	for _, line := range lines {
		for _, segment := range denyrules.Segments(line) {
			out = append(out, segment)
			if cleaned := denyrules.NormalizePaths(segment); cleaned != segment {
				out = append(out, cleaned)
			}
		}
	}
	return out
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
	if !filepath.IsAbs(cwd) {
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
	return "this host declares " + rule.what +
		", and a brokered command may not read, copy or move what is declared. " +
		"Its contents are covered by nothing on the way back: a declared file is " +
		"one faramir either never reads or reads a single ref out of, so there is " +
		"no value to replace in this command's output.\n\n" +
		"Reading it is the operator's, either outside faramir or after " +
		rule.remedy + ". Changing it where it stands is not refused: this covers " +
		"reading, copying and moving alone."
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
