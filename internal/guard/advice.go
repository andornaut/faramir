package guard

import (
	"fmt"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
)

// A refusal reaches a coding agent in the middle of a task, so it says what
// was refused and gives at most one hint, on an indented line under it. Why the
// rule exists is in docs/configuration.md, not here.
type refusal struct {
	// head is the command form's first line after "Blocked: ".
	head string
	// subject is what a refused path is, as a noun phrase, for the file tool
	// form: "<path> is <subject>". Empty for a kind a file tool cannot meet.
	subject string
	// hint is the one thing the agent may do instead, or empty.
	hint string
}

// command is the refusal of a shell command.
func (r refusal) command() string {
	return "Blocked: " + r.head + indented(r.hint)
}

// file is the refusal of a file tool call naming path.
func (r refusal) file(path string) string {
	return "Blocked: " + path + " is " + r.subject + "." + indented(r.hint)
}

// indented is a line of detail under a refusal's first line, or nothing.
func indented(line string) string {
	if line == "" {
		return ""
	}
	return "\n  " + line
}

// useRef is the hint for any declared path: a value reached by ref is reached
// without the file being named.
const useRef = "Use the value by ref: `faramir run --env NAME=faramir://<ref>`."

var (
	refuseBlocked = refusal{
		head:    "this command names a path the operator blocked.",
		subject: "a path the operator blocked",
		hint:    useRef,
	}
	refuseBlockedStrict = refusal{
		head:    "this command names a path the operator blocked as strict.",
		subject: "a path the operator blocked as strict",
		hint:    useRef,
	}
	refuseLinked = refusal{
		head:    "this command names a file a link reads.",
		subject: "a file a link reads",
		hint:    useRef,
	}
	refuseLinkedStrict = refusal{
		head:    "this command names a file a strict link reads.",
		subject: "a file a strict link reads",
		hint:    useRef,
	}
	// No entry declares faramir's own directories and no removal takes them
	// back: they are rendered from the layout on every run.
	refuseOwnPath = refusal{
		head:    "this command names one of faramir's own directories.",
		subject: "in one of faramir's own directories",
		hint:    "Ask the operator.",
	}
	// The safe default, for a rule no marker classified: what is true of any
	// declared path. Disclosure rather than one of the narrower messages,
	// because being wrong this way costs a detour and being wrong the other way
	// tells an agent that the operator's own secret is faramir's file.
	refuseDeclared = refusal{
		head:    "this command names a path in the blocks or the links on this host.",
		subject: "in the blocks or the links on this host",
		hint:    useRef,
	}
	// A [[secret.block]] entry naming a command rather than a path: telling
	// somebody who ran `op read` that a path is refused names nothing they typed.
	// The removal is spelled as the operator types it: it writes the config, so
	// it needs root, and block rm takes its subject as a flag.
	refuseCommand = refusal{
		head: "this command is blocked on this host.",
		hint: "To unblock, ask the operator to run `sudo faramir block rm --command <command>`.",
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
		hint:    "Ask the operator to make the change.",
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
	adviceOperator          = refuseOperator.command()
	adviceOwn               = refuseOwnAction.command()
)

// refusals is the refusal per catalogue kind, which is the same vocabulary the
// broker answers from. The broker words its first line about a brokered
// command and gives the same hint per kind; what the two share is what decides
// which sentence, so a kind cannot be answered here and forgotten there.
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
const pathAdvice = "Blocked: %s is protected on this host.\n  " + useRef

// fileAdviceFor is what a refused file tool is told: the refusal its kind
// carries, said about the path rather than about a command, with the same hint
// a shell gets.
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
