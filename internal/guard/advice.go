package guard

import (
	"fmt"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
)

// A refusal reaches a coding agent in the middle of a task, so it leads with
// what was refused and puts each thing it may do instead on an indented line
// of its own. Why the rule exists is in docs/configuration.md, not here.
type refusal struct {
	// head is the command form's first line after "Blocked: ": what the command
	// did, and where a path kind applies, which tools may not name it.
	head string
	// subject is what a refused path is, as a noun phrase, for the file tool
	// form: "<path> is <subject>". Empty for a kind a file tool cannot meet.
	subject string
	// path is a declared path or one of faramir's own directories. The command
	// form then says how to write about the path, a rule matched against the
	// text of a command refusing a heredoc that quotes it like the command
	// itself, and the file tool form says shell commands may not name it either.
	path bool
	// instead is what the agent may do, most useful first.
	instead []string
}

// command is the refusal of a shell command.
func (r refusal) command() string {
	lines := r.instead
	if r.path {
		lines = append([]string{writeAboutPath}, lines...)
	}
	return "Blocked: " + r.head + indented(lines)
}

// file is the refusal of a file tool call naming path.
func (r refusal) file(path string) string {
	said := "Blocked: " + path + " is " + r.subject + ". This tool call was not made."
	if r.path {
		said += " Shell commands may not name it either."
	}
	return said + indented(r.instead)
}

// indented is lines as the detail under a refusal's first line.
func indented(lines []string) string {
	var b strings.Builder
	for _, line := range lines {
		b.WriteString("\n  " + line)
	}
	return b.String()
}

// The scope sentences. A loose entry is refused to the agent's shell and file
// tools; a strict entry and faramir's own directories are refused to brokered
// commands as well.
const (
	scopeLoose  = "Shell commands may not name it, even quoted, and file tools may not open it."
	scopeStrict = "Shell commands, brokered commands and file tools may not name it, even quoted."
)

const writeAboutPath = "To write about the path, use your editing tool, not a shell heredoc."

// useRef holds for any declared path: a value reached by ref is reached
// without the file being named.
const useRef = "Use the value by ref: `faramir run --env NAME=faramir://<ref>`. " +
	"`faramir refs` lists refs."

// useRoute is the brokered route, open for a loose entry only: the broker holds
// the same entries and refuses a strict one to every brokered command.
const useRoute = "Use the credential through `faramir run`, which refuses commands that print the file."

// The removals spelled as the operator types them: each writes the config, so
// it needs root, and block rm takes its subject as a flag.
const (
	unblockPath    = "To unblock, ask the operator to run `sudo faramir block rm --path <path>`."
	unblockCommand = "To unblock, ask the operator to run `sudo faramir block rm --command <command>`."
	// A link's removal takes the ref with it, which is what the agent would use
	// instead, so the line says so.
	unlink = "Removing the link also removes its ref. Only the operator can, with `sudo faramir link rm <ref>`."
)

var (
	refuseBlocked = refusal{
		head:    "this command names a path the operator blocked. " + scopeLoose,
		subject: "a path the operator blocked",
		path:    true,
		instead: []string{useRoute, useRef, unblockPath},
	}
	refuseBlockedStrict = refusal{
		head:    "this command names a path the operator blocked as strict. " + scopeStrict,
		subject: "a path the operator blocked as strict",
		path:    true,
		instead: []string{useRef, unblockPath},
	}
	refuseLinked = refusal{
		head:    "this command names a file a link reads. " + scopeLoose,
		subject: "a file a link reads",
		path:    true,
		instead: []string{useRef, useRoute, unlink},
	}
	refuseLinkedStrict = refusal{
		head:    "this command names a file a strict link reads. " + scopeStrict,
		subject: "a file a strict link reads",
		path:    true,
		instead: []string{useRef, unlink},
	}
	// No entry declares faramir's own directories and no removal takes them
	// back: they are rendered from the layout on every run.
	refuseOwnPath = refusal{
		head:    "this command names one of faramir's own directories. " + scopeStrict,
		subject: "in one of faramir's own directories",
		path:    true,
		instead: []string{useRef,
			"This built-in rule cannot be removed. Ask the operator if you need access."},
	}
	// The safe default, for a rule no marker classified: what is true of any
	// declared path, with both removals. Disclosure rather than one of the
	// narrower messages, because being wrong this way costs a detour and being
	// wrong the other way tells an agent that the operator's own secret is
	// faramir's file.
	refuseDeclared = refusal{
		head:    "this command names a path in the blocks or the links on this host. " + scopeLoose,
		subject: "in the blocks or the links on this host",
		path:    true,
		instead: []string{useRoute, useRef,
			"To lift it, ask the operator: `sudo faramir block rm --path <path>` for a block, " +
				"`sudo faramir link rm <ref>` for a link. `faramir block ls` and `faramir link ls` show which."},
	}
	// A [[secret.block]] entry naming a command rather than a path: telling
	// somebody who ran `op read` that a path is refused names nothing they typed.
	refuseCommand = refusal{
		head: "this command is blocked on this host, in your shell and in brokered commands.",
		instead: []string{
			"To write about the command, use your editing tool, not a shell heredoc.",
			unblockCommand},
	}
	// A command that acts on the install rather than through it. The account the
	// agent runs as could not carry it out, so the refusal saves the detour of
	// finding that out from a permission error.
	refuseOperator = refusal{
		head: "this is an operator command, with or without sudo. Ask the operator to run it.",
	}
	// Acting on faramir's own files, accounts or units discloses nothing, so
	// this offers no brokered route: a brokered command runs as an account with
	// less reach rather than more.
	refuseOwnAction = refusal{
		head:    "this command changes faramir's own file, account or unit.",
		subject: "faramir's own file, account or unit",
		instead: []string{"Changes are refused, including through `faramir run`. " +
			"Ask the operator to make the change."},
	}
)

// The command form of each, as adviceFor returns it.
var (
	adviceBlockedPath       = refuseBlocked.command()
	adviceBlockedStrictPath = refuseBlockedStrict.command()
	adviceLinkedPath        = refuseLinked.command()
	adviceLinkedStrictPath  = refuseLinkedStrict.command()
	adviceOwnPath           = refuseOwnPath.command()
	adviceDeclared          = refuseDeclared.command()
	adviceCommand           = refuseCommand.command()
	adviceOperator          = refuseOperator.command()
	adviceOwn               = refuseOwnAction.command()
)

// refusals is the refusal per catalogue kind, which is the same vocabulary the
// broker answers from. Two tables rather than one because the two tiers say
// different things: a brokered refusal talks about the account on the far side
// of it, and this one talks about your tools and your shell. What they share is
// what decides which sentence, so a kind cannot be answered here and forgotten
// there.
var refusals = map[denyrules.Kind]refusal{
	denyrules.KindOwn:           refuseOwnPath,
	denyrules.KindBlocked:       refuseBlocked,
	denyrules.KindBlockedStrict: refuseBlockedStrict,
	denyrules.KindLinked:        refuseLinked,
	denyrules.KindLinkedStrict:  refuseLinkedStrict,
	denyrules.KindCommand:       refuseCommand,
	denyrules.KindOperator:      refuseOperator,
	denyrules.KindOwnAction:     refuseOwnAction,
}

// byKind is the command form of refusals.
var byKind = func() map[denyrules.Kind]string {
	out := make(map[denyrules.Kind]string, len(refusals))
	for kind, r := range refusals {
		out[kind] = r.command()
	}
	return out
}()

// refusalFor picks the refusal that matches why the command was refused.
// Every rule this install rendered carries its kind as a named group, so the
// pattern says which message it wants and nothing has to be recognised by a
// substring of itself.
//
// Unclassified means a file an older install rendered, from before the kinds.
// It gets the disclosure message, which is the larger half and the safer
// default: being wrong that way costs a detour, and being wrong the other way
// tells an agent that the operator's own secret is faramir's file.
func refusalFor(pattern string) refusal {
	for _, kind := range denyrules.Kinds() {
		if strings.Contains(pattern, denyrules.KindMarker(kind)) {
			return refusals[kind]
		}
	}
	return refuseDeclared
}

// adviceFor is the refusal of a shell command the pattern matched.
func adviceFor(pattern string) string {
	return refusalFor(pattern).command()
}

// deniedCommand is the whole refusal of a shell command: the kind's message,
// then the command in a compound line the rule matched, then what it matched.
// A hook answers for the whole tool call, so naming the segment is what tells
// the agent which part of the line to change.
func deniedCommand(command, pattern string) string {
	said := adviceFor(pattern)
	if segment := matchingSegment(command, pattern); segment != "" {
		said += "\n  whole call refused for: " + shortSegment(segment)
	}
	return said + "\n  matched: " + matchedNote(command, pattern)
}

// matchedNote is what the refusal says about the rule that answered: the text
// of the command the rule matched, and the head of the rule itself where that
// text cannot be recovered.
//
// The text rather than the rule. Subjects are packed into one alternation per
// kind, so the head of a rule is the same handful of characters whatever entry
// fired, and a refusal that printed it told a reader nothing about which of a
// few hundred paths it had named. What was matched is what a reader has to see
// to know what to stop naming.
func matchedNote(command, pattern string) string {
	if matched := matchedText(command, pattern); matched != "" {
		return shortSegment(matched)
	}
	return "deny pattern " + shortPattern(pattern)
}

// matchedText is the part of the command the reported rule matched, empty
// where the rule matched a spelling normalisation produced rather than
// anything that was written.
//
// The segment as it was typed, and only that. decide asks about the normalised
// spelling as well, so a rule can answer a word nobody wrote: quoting that back
// tells the agent to stop naming something it never named, which is the failure
// matchingSegment exists to avoid on the other half of the same message.
func matchedText(command, pattern string) string {
	for _, p := range loadPatterns() {
		if p.source != pattern {
			continue
		}
		for _, segment := range denyrules.Segments(stripFaramirCalls(command)) {
			if !p.re.MatchString(segment) || !p.re.MatchString(withoutWrapper(segment)) {
				continue
			}
			if found := p.re.FindString(segment); found != "" {
				return found
			}
		}
	}
	return ""
}

// shortPattern is a rendered rule as much of it as identifies which one it was.
// The whole of one runs past 600 characters of alternation, all of it going into
// the transcript on every refusal, where nothing reads a regular expression: the
// operator finds the rule in the file by its opening, and the model needs none
// of it. `faramir block ls` prints them in full.
func shortPattern(pattern string) string {
	const keep = 60
	if len(pattern) <= keep {
		return pattern
	}
	return pattern[:keep] + "…"
}

// shortSegment bounds the command a refusal quotes back. Longer than a pattern's
// cap, this being the part the agent has to recognise as its own, and a command
// cut at sixty characters usually loses the argument that matched. Cut on a rune
// boundary: a pattern is ASCII and a command is whatever was typed.
func shortSegment(segment string) string {
	const keep = 160
	runes := []rune(segment)
	if len(runes) <= keep {
		return segment
	}
	return string(runes[:keep]) + "…"
}

// pathAdvice is what a refused file tool is told for a kind it cannot meet: a
// command entry and the rules about faramir's own commands match a verb and a
// path together, so a tool call carrying a path alone reaches none of them.
const pathAdvice = "Blocked: %s is protected on this host. This tool call was not made." +
	"\n  " + useRef

// fileAdviceFor is what a refused file tool is told: the refusal its kind
// carries, said about a call that was not made rather than a command that
// would have run. The kinds differ in the list the entry is in and the removal
// that lifts it, which is the same answer a shell gets.
//
// The rules about faramir's own are among those a file tool does reach: the
// deny list is asked about this path as a read and as a write, and `tee` is a
// write command, so an agent's own hook file matches the rule that refuses
// replacing it.
func fileAdviceFor(pattern, path string) string {
	if r := refusalFor(pattern); r.subject != "" {
		return r.file(path)
	}
	return fmt.Sprintf(pathAdvice, path)
}
