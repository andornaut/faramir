package denyrules

// The rules built over the declared paths, one per kind of entry.

import (
	"strings"
)

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
func subjectRule(kind Kind, subjects []string) []string {
	if len(subjects) == 0 {
		return nil
	}
	open := `(`
	if kind != "" {
		open = KindMarker(kind)
	}
	return []string{open + strings.Join(subjects, `|`) + `)`}
}

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
func NamingAs(kind Kind, subjects []string) []string {
	return subjectRule(kind, subjects)
}

// KindMarker is what a rule of that kind opens with, for a reader that has the
// rule as text rather than as a compiled regexp. The guard's shipped file is a
// list of patterns and its refusal picks a message by what the pattern says, so
// the marker is written once here rather than spelled again there.
func KindMarker(kind Kind) string {
	return `(?P<` + string(kind) + `>`
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
		read:    readCommands + ArgSpan + alternation,
		input:   `<\s*\S*` + alternation,
		binding: binding + boundAlternation,
	}, true
}
