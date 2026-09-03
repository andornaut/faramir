package guard

import (
	"fmt"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
)

// adviceOperator is for a command that is the operator's to run. The account
// this agent runs as could not have carried it out, so the refusal saves the
// detour of finding that out from a permission error.
const adviceOperator = "Blocked: this is an operator command. It changes the faramir install, so it is " +
	"refused with or without sudo, and your account could not run it anyway.\n\nAsk the " +
	"operator to run it. You can run `faramir run`, `faramir refs`, `faramir status`, " +
	"`faramir redact`, and the commands that only describe the install: `faramir doctor`, " +
	"`faramir block ls`, `faramir link ls` and `faramir reader ls`.\n\nWhen `faramir doctor` " +
	"says to run it as root, that line is for the operator. Your account cannot make those " +
	"checks, and running the command under sudo is refused here."

// The declared-path messages, one per kind of entry, chosen by the named group
// the rule carries. The rule itself is the same shape in all three: a path
// named at all is refused, whatever the command would do with it. What differs
// is how the agent stops being refused, and a message that could not say which
// had to name two commands and a way to tell them apart.
//
// adviceRefs is the half that holds for any declared path, faramir's own
// directories included: a value reached by ref is reached without the file
// being named, so no rule about the path is in the way.
// adviceNamed is what the rule does, which is the half none of the four
// messages differ on.
// The escape is in the same sentence as the refusal because the commonest way
// to meet this rule is to write about the path rather than to read it: a rule
// matched against the text of a command cannot tell a name being used from one
// being quoted, so a heredoc that documents an operator command is refused like
// the command itself. Saying so here is what saves the turn spent finding out.
const adviceNamed = ", so any command that names it is refused, in your shell and in your tools, " +
	"whatever the command would do with it. That includes writing about it: a rule matched " +
	"against the text of a command cannot tell a name being written from one being used. To " +
	"write a document that quotes this path, use your editing tool, not a shell heredoc."

const adviceRefs = "If the value has a `faramir://` ref, `faramir refs` lists it, and " +
	"`faramir run --env NAME=faramir://<ref>` uses it without naming the file."

// adviceRoute is the brokered route, for the entries where it is open. It is
// not always: the broker holds the same entries and refuses a command that
// would read the file. It is worth naming anyway, a command that only uses a
// credential being the ordinary case.
const adviceRoute = "\n\nA brokered command is treated differently: `faramir run` refuses the commands " +
	"that would read the file and allows the rest, so a command that only uses the credential may " +
	"run there. " + adviceRefs

// adviceUnblockPath is the removal spelled as the operator has to type it.
// Both halves matter and neither is guessable from the other: the command
// writes the config, so it needs root, and it takes the path as a flag rather
// than as an operand, so the bare command name is an invocation that fails.
// Naming it short taught the operator a command they then had to work out.
const adviceUnblockPath = "`sudo faramir block rm --path <path>`, which needs " +
	"root because it writes the config."

// adviceUnblockCommand is the same removal for an entry naming a command.
const adviceUnblockCommand = "`sudo faramir block rm --command <command>`, which " +
	"needs root because it writes the config."

// adviceBlockedPath is for a path a [[secret.block]] entry names. The entry
// exists to refuse and nothing else, so removing it is the whole remedy.
const adviceBlockedPath = "Blocked: the operator blocked this path on this host" + adviceNamed + adviceRoute +
	"\n\nOtherwise ask the operator, who can unblock it with " + adviceUnblockPath +
	" `faramir block ls` lists the blocked paths."

// adviceLinkedPath is for the file a [[secret.link]] entry reads. Removing the
// entry takes the refusal back and the ref with it, so the ref is the thing to
// reach for first: it is what the link is for, and it answers without the file
// being named.
const adviceLinkedPath = "Blocked: a link reads this file on this host" + adviceNamed + adviceRoute +
	"\n\nUse the ref instead of the file: that is what the link is for. `faramir link ls` lists the " +
	"links and the files they read. Only the operator can remove a link, with `faramir link rm`, " +
	"and that removes the ref too."

// adviceNoRoute is what adviceRoute becomes for a strict entry: the broker
// holds the same entry and refuses a command that names it at all, so offering
// the brokered route would spend a turn on a second refusal. The ref is still a
// route, and is the only one, so it is what this says instead.
const adviceNoRoute = "\n\nThe broker holds the same entry, and the operator marked it strict: " +
	"a brokered command that names the path is refused too, whatever it would do with it. " +
	adviceRefs

// adviceBlockedStrictPath and adviceLinkedStrictPath are the two entry
// messages for an entry written strict. The same wording as the loose pair
// with the brokered route taken out, rather than a sentence bolted on: an
// agent that reads "may go through there" spends the turn finding out it may
// not.
const adviceBlockedStrictPath = "Blocked: the operator blocked this path on this host" + adviceNamed +
	adviceNoRoute + "\n\nOtherwise ask the operator, who can unblock it with " + adviceUnblockPath +
	" `faramir block ls` lists the blocked paths and marks the strict ones."

const adviceLinkedStrictPath = "Blocked: a link reads this file on this host" + adviceNamed + adviceNoRoute +
	"\n\nUse the ref instead of the file: that is what the link is for. `faramir link ls` lists the " +
	"links and the files they read. Only the operator can remove a link, with `faramir link rm`, " +
	"and that removes the ref too."

// adviceOwnPath is for a directory this install occupies. No entry declares
// these and no removal takes them back: they are rendered from the layout on
// every run, so a message offering a removal command would name a remedy that
// does not exist.
const adviceOwnPath = "Blocked: this is one of faramir's own directories" + adviceNamed + "\n\n" + adviceRefs +
	" A brokered command cannot reach the directory either: `faramir run` holds the same rules and " +
	"runs as an account with less access than yours.\n\nThere is no entry to remove. These rules " +
	"are rendered from the install's layout on every run and appear in neither `faramir block ls` " +
	"nor `faramir link ls`. If this is deliberate, ask the operator."

// adviceDeclared is the safe default, for a rule no marker classified. It says
// what is true of any declared path and leaves the reader to find which kind
// applies, which is the most a message can do when the rule does not say.
//
// Disclosure rather than one of the narrower messages, because being wrong this
// way costs a detour and being wrong the other way tells an agent that the
// operator's own secret is faramir's file.
const adviceDeclared = "Blocked: this path is in the blocks or the links on this host" + adviceNamed + adviceRoute +
	"\n\nOtherwise ask the operator, who can unblock it: `sudo faramir block rm --path <path>` " +
	"for a blocked path, `faramir link rm` for a file a link reads. Both write the config and " +
	"need root. `faramir block ls` and `faramir link ls` show which it is, and you may run both. " +
	"The install's own directories are on neither list and cannot be removed: their rules are " +
	"rendered from the layout on every run."

// adviceCommand is for a `[[secret.block]]` entry naming a command rather than a
// path. The remedy is the same shape and the subject is not: telling somebody
// who ran `op read` that a path is declared names nothing they typed.
const adviceCommand = "Blocked: this command is in the blocks on this host, so neither your shell nor a " +
	"brokered command may run it.\n\nThe words are matched at the start of a command only, so " +
	"the same words inside an argument or a path are allowed. A line of a heredoc is read as a " +
	"command, so to write a document that quotes this command, use your editing tool, not a " +
	"shell heredoc. If the work needs the command, ask the operator, who can unblock it with " +
	adviceUnblockCommand

// adviceOwn is for the rules that are not about disclosure. Acting on
// faramir's own files, accounts or units discloses nothing, and the disclosure
// advice would offer `faramir run` as the way to proceed: a brokered command
// runs as an account with less reach rather than more.
const adviceOwnOpening = "Blocked: this is "

const adviceOwn = adviceOwnOpening + "faramir's own file, account or unit. It would disclose nothing, " +
	"but it would change or stop what keeps credentials out of this conversation. " +
	"`faramir run` is no way round it: a brokered command has less access than you." +
	"\n\nIf this is deliberate, ask the operator."

// byKind is the message per catalogue kind, which is the same vocabulary the
// broker answers from. Two tables rather than one because the two tiers say
// different things: a brokered refusal talks about the account on the far side
// of it, and this one talks about your tools and your shell. What they share is
// what decides which sentence, so a kind cannot be answered here and forgotten
// there.
var byKind = map[denyrules.Kind]string{
	denyrules.KindOwn:           adviceOwnPath,
	denyrules.KindBlocked:       adviceBlockedPath,
	denyrules.KindBlockedStrict: adviceBlockedStrictPath,
	denyrules.KindLinked:        adviceLinkedPath,
	denyrules.KindLinkedStrict:  adviceLinkedStrictPath,
	denyrules.KindCommand:       adviceCommand,
	denyrules.KindOperator:      adviceOperator,
	denyrules.KindOwnAction:     adviceOwn,
}

// adviceFor picks the explanation that matches why the command was refused.
// Every rule this install rendered carries its kind as a named group, so the
// pattern says which message it wants and nothing has to be recognised by a
// substring of itself.
//
// Unclassified means a file an older install rendered, from before the kinds.
// It gets the disclosure message, which is the larger half and the safer
// default: being wrong that way costs a detour, and being wrong the other way
// tells an agent that the operator's own secret is faramir's file.
func adviceFor(pattern string) string {
	for _, kind := range denyrules.Kinds() {
		if strings.Contains(pattern, denyrules.KindMarker(kind)) {
			return byKind[kind]
		}
	}
	return adviceDeclared
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

// pathAdvice is what a refused file tool is told. Its own wording rather than
// the command one's: nothing ran, so "this command" would name something that
// never happened, and the way through is the same either way.
const pathAdvice = "Blocked: %s is key material or one of faramir's own files, so this tool call " +
	"was not made.\n\nA value reaches a command through the broker: use `faramir run`. " +
	"`faramir refs` lists what exists."

// fileAdviceFor is what a refused file tool is told: the message its kind
// carries, with the clause about a command swapped for the call that was
// actually refused. The kinds differ in the list the entry is in and the
// removal that lifts it, and a file tool's refusal named neither: it said "key
// material or one of faramir's own files", which is the two answers at once and
// no remedy for either.
//
// The kinds a file tool cannot meet fall back to the flat wording. A command
// entry and the rules about faramir's own commands match a verb and a path
// together, so a tool call carrying a path alone reaches none of them.
func fileAdviceFor(pattern, path string) string {
	said := adviceFor(pattern)
	if strings.Contains(said, adviceNamed) {
		return strings.Replace(said, adviceNamed, adviceFileNamed(path), 1)
	}
	// The rules about faramir's own, which a file tool does reach: the deny list
	// is asked about this path as a read and as a write, and `tee` is a write
	// command, so an agent's own hook file matches the rule that refuses
	// replacing it. Its message stands as it is with the path named, and it is
	// the one message that must not fall back: the fallback offers `faramir run`
	// as the way through, which this rule says in as many words it is not.
	if rest, found := strings.CutPrefix(said, adviceOwnOpening); found {
		return "Blocked: this tool call was not made. " + path + " is " + rest
	}
	return fmt.Sprintf(pathAdvice, path)
}

// adviceFileNamed is adviceNamed for a tool call: the same rule, said about a
// call that did not happen rather than about a command that would have run.
// The heredoc clause goes with it, an editing tool being what the reader is
// already holding.
func adviceFileNamed(path string) string {
	return ", so this tool call was not made. " + path + " is refused to your file " +
		"tools and to your shell, whatever either would do with it."
}
