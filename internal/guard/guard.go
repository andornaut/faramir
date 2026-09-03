// Package guard is a PreToolUse hook, run as `faramir guard`: it denies Bash
// commands that would put a secret in the context, and rewrites the rest to run
// under the redactor. Reads the hook payload on stdin, writes a decision on
// stdout. It is not the security boundary; see docs/design.md.
package guard

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/version"
)

// No compiled-in verb rules. What a command does rather than what it points at
// is the operator's to declare, `faramir block add --command`, and a declared
// one is rendered into the shipped file rather than carried here: the fallback
// is what holds when that file cannot be read, and it can no more carry a
// declaration than it can carry a [[secret.block]] path.

func decide(command string) (string, bool) {
	stripped := stripFaramirCalls(command)
	// Per command rather than per line. A pattern matched against the whole
	// string cannot tell one command from the next, so a reader in the first
	// reached a path named in the second; quoting is what decides where one
	// ends, and a pattern cannot read quoting.
	//
	// Each segment twice: as it was written, and with its paths in their
	// shortest spelling. A rule carries one spelling of a path, so "/etc//x" and
	// "/etc/y/../x" reached a file the rule names and matched nothing.
	// Normalising in addition rather than instead, because cleaning only ever
	// shortens a word: anything the original matched, it still matches.
	//
	// Patterns outer, so the rule reported is the first one the file carries
	// that matches anywhere, as it was when the line was matched whole.
	segments := denyrules.Segments(stripped)
	spellings := make([]string, 0, len(segments)*2)
	for _, segment := range segments {
		spellings = append(spellings, segment)
		if cleaned := denyrules.NormalizePaths(segment); cleaned != segment {
			spellings = append(spellings, cleaned)
		}
	}
	for _, p := range loadPatterns() {
		for _, spelling := range spellings {
			if !p.re.MatchString(spelling) {
				continue
			}
			// Asked again without the wrapper invocation. A rule that matched
			// only because the guard's own output named it has found nothing:
			// see withoutWrapper. One that still matches found something else.
			if !p.re.MatchString(withoutWrapper(spelling)) {
				continue
			}
			return p.source, true
		}
	}
	return "", false
}

// matchingSegment returns the one command in a line that the reported pattern
// matched. A hook answers for the whole tool call, so a single refused segment
// refuses the batch, and a message naming only the pattern leaves the agent to
// work out which part of a compound line was at fault. Naming the wrong part is
// what an agent then does: it rewrites the innocent half, is refused again, and
// reports the rule as a false positive against a command the rule never saw.
//
// Empty for a line holding one command, where the pattern is already the whole
// answer, and empty when no segment matches alone: a pattern can match a
// spelling that normalisation produced rather than anything that was written,
// and a message quoting a command the agent did not type is worse than none.
func matchingSegment(command, pattern string) string {
	segments := denyrules.Segments(stripFaramirCalls(command))
	if len(segments) < 2 {
		return ""
	}
	for _, p := range loadPatterns() {
		if p.source != pattern {
			continue
		}
		for _, segment := range segments {
			// The same readings decide asked, and the same exemption: without it
			// this names the wrapper invocation decide deliberately let through,
			// which is the "wrong part of the line" failure it exists to avoid.
			for _, spelling := range []string{segment, denyrules.NormalizePaths(segment)} {
				if p.re.MatchString(spelling) && p.re.MatchString(withoutWrapper(spelling)) {
					return segment
				}
			}
		}
		break
	}
	return ""
}

// Run is the `faramir guard` subcommand.
func Run(args []string) int {
	// Parsed before stdin is read, so running this by hand does not hang on a
	// payload.
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	hostName := fs.String("host", "", "the agent whose hook dialect to speak")
	// The account-wide half. It refuses a file tool naming key material and
	// leaves a command alone: routing one would work in any tree, so what holds
	// it to enrolled ones is the operator having said which those are.
	// Claude Code is the one host where a rewrite has to be approved: a rewritten
	// command matches no permission rule, and the rule that would match one is
	// refused outright ("'source' evaluates arguments as shell code"). So the
	// allow that makes routing work is also an allow for every command the list
	// does not name, which is a trade an operator makes per tree rather than for
	// a whole account.
	//
	// Registered account-wide it answers only about what the list refuses, and
	// says nothing about anything else. A silent answer leaves the host's own
	// permission flow exactly as it was.
	denyOnly := fs.Bool("deny-only", false,
		"refuse what the deny list names and approve nothing, for an account-wide registration")
	showVersion := fs.Bool("version", false, "print the version and exit")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if *showVersion {
		fmt.Println("faramir " + version.Version)
		return 0
	}
	// Also before stdin: an unknown host is a misregistration, and every command
	// would otherwise be answered in a dialect the agent ignores.
	activeHost, err := lookupHost(*hostName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir guard: %v\n", err)
		return 2
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		// The same answer an unreadable payload gets below: stdin that cannot be
		// read at all is no less an unguardable payload than one that arrived and
		// would not parse.
		return emit(activeHost.deny(unreadablePayload))
	}
	decode := activeHost.decode
	if decode == nil {
		decode = decodeToolInput
	}
	p, err := decode(data)
	if err != nil {
		// Fails closed, the way faramir's own plugin does on the same input. A
		// payload this cannot read is the host's shape having changed, and on the
		// hook that guards every Bash call the alternative is returning quietly
		// and leaving every command in every enrolled tree unredacted. Refusing
		// says so in the transcript, where somebody reads it.
		return emit(activeHost.deny(unreadablePayload))
	}
	// The directory a relative path in this call is relative to: the host's own
	// word for it where the payload carries one, and otherwise this process's,
	// which is the agent's only where the host started the guard from there. An
	// error leaves it empty, which asks the path as written.
	//
	// Load-bearing for the patch branch below rather than a convenience. Codex
	// emits a header path either absolute or relative, observed both ways at one
	// version (see TestTheCodexContractMatchesACapturedPayload), and a relative
	// one asked as written matches no rule spelled absolutely. So a patch naming
	// `../.config/faramir/<file>` from a tree beside the config is what this
	// resolution catches and nothing else would.
	cwd := p.Cwd
	if cwd == "" && activeHost.runsInAgentCwd {
		cwd, _ = os.Getwd()
	}
	// Before the tool gate and before the command is read: a patch envelope is
	// not a command, so scanning it as one would refuse a patch for the text
	// inside it and routing one through the wrapper would produce a patch that no
	// longer applies. What it is asked instead is the files its headers name.
	if activeHost.patchTool != "" && p.ToolName == activeHost.patchTool {
		// An envelope that is not where this expects it is refused rather than
		// allowed. This is the one tool the agent writes files with, and the only
		// thing refusing it a path is this branch, so a key that has moved would
		// otherwise leave every patch unexamined and say nothing. The sibling
		// branches fail closed on a payload they cannot read; so does this one.
		if strings.TrimSpace(p.ToolInput.Command) == "" {
			return emit(activeHost.deny(unreadablePatch))
		}
		if path, pattern, denied := refusedPatchPath(cwd, p.ToolInput.Command); denied {
			return emit(activeHost.deny(fileAdviceFor(pattern, path)))
		}
		return 0
	}
	// Before the tool gate: a file tool is one this host runs no commands
	// through, so gating on the name first would leave every read unexamined on
	// the host that has nothing else to refuse one.
	command := commandOf(p)
	if command == "" && activeHost.refusesPaths {
		if path, pattern, denied := refusedPath(cwd, p.RawInput); denied {
			// The kind's own message, not the pattern: the list is asked about a
			// read of this path, so what answered is a reader-verb alternation that
			// describes how the question was put rather than why the file is
			// refused. What the kind carries is the list the entry is in and the
			// removal that lifts it, which is the same answer a shell gets.
			return emit(activeHost.deny(fileAdviceFor(pattern, path)))
		}
	}
	if !activeHost.handles(p.ToolName) {
		return 0
	}
	if command == "" {
		// A plugin host is asked about every tool call, so a call with no command
		// is the ordinary case: a read, an edit, anything that runs nothing. Its
		// own SHELL_TOOLS check is what fails closed there, before this is called.
		if activeHost.anyShellTool {
			return 0
		}
		// A tool the host names but does not run commands through: Claude Code's
		// BashOutput, which reads a running command's buffer. It starts nothing,
		// and what filled that buffer went through the redactor when it was
		// started, so carrying no command is what it always looks like.
		if !activeHost.wraps(p.ToolName) {
			return 0
		}
		// A hook host answers only for the tools it runs commands through, so
		// reaching here means the one it wraps arrived carrying no command. Same
		// reasoning as the unreadable payload above: the shape changed, and
		// returning quietly leaves the tree unredacted.
		return emit(activeHost.deny(noCommandString))
	}

	if pattern, denied := decide(command); denied {
		note := "\n\n(matched: " + matchedNote(command, pattern) + ")"
		if segment := matchingSegment(command, pattern); segment != "" {
			note = "\n\nOne command in the line matched. The whole call is refused" +
				" because a hook answers for the whole line. The command to change:" +
				"\n\n    " + shortSegment(segment) +
				"\n\n(matched: " + matchedNote(command, pattern) + ")"
		}
		return emit(activeHost.deny(adviceFor(pattern) + note))
	}

	// The same question the patch branch above asks, of a command that runs the
	// patch tool itself: the documented way to invoke it from a shell is with the
	// envelope in a heredoc, and the list above reads a heredoc body as commands,
	// quoted delimiter or not, so it has already seen each header line as written
	// and refused one that names a declared path. What it does not reach is a
	// header path in another spelling, relative to cwd or under "~", which is
	// resolved and asked about again here.
	if path, pattern, denied := refusedPatchCommand(activeHost, cwd, command); denied {
		return emit(activeHost.deny(fileAdviceFor(pattern, path)))
	}

	// Everything the list names has been refused by here, which is the whole of
	// what an account-wide registration does: approving the rest is what it
	// exists not to do, and a silent answer leaves the host's own permission
	// flow as it was.
	if *denyOnly {
		return 0
	}

	// A deny list only covers what someone thought to name, so everything else is
	// rewritten to run under the redactor rather than refused. Exit status and
	// both streams are preserved; known values come back as tokens.
	wrapped, ok := wrap(activeHost, command, p)
	if !ok {
		return 0
	}
	// Every field back with only the command changed, or the command alone where
	// the host merges what it is handed into the call's own arguments.
	updated := map[string]any{}
	if !activeHost.mergesInput {
		maps.Copy(updated, p.RawInput)
	}
	updated[activeHost.commandField()] = wrapped

	// The rewrite approves as well as rewrites: a wrapper that redacts output
	// cannot be allow-listed, the permission matcher refusing rules naming source,
	// eval or a compound statement, so "ask" would prompt on every command with no
	// rule able to pre-approve any of it. For Bash, the deny list above replaces
	// the permission prompt.
	return emit(activeHost.rewrite(updated))
}

// The two refusals that are about this hook rather than about the command. Both
// name what to do, because both reach the model rather than the operator: an
// agent that is told to stop and why can say so, where one that meets a silent
// refusal retries.
const (
	unreadablePayload = "Blocked: faramir's guard could not read this tool call, so it could not decide " +
		"whether the command discloses a credential.\n\nTell the operator that `faramir " +
		"guard` did not understand its input. Until that is fixed, nothing this tree runs is " +
		"redacted."
	noCommandString = "Blocked: faramir's guard received a shell tool call with no command, so " +
		"there was nothing to check.\n\nTell the operator: the tool's input is not the " +
		"shape `faramir guard` reads."
	unreadablePatch = "Blocked: faramir's guard could not read this patch, so it could not " +
		"tell which files the patch writes.\n\nTell the operator: the patch tool's input is " +
		"not the shape `faramir guard` reads. Until that is fixed, this tool could write " +
		"any file on the host."
)

func emit(document map[string]any) int {
	out, err := json.Marshal(document)
	if err != nil {
		return 0
	}
	_, _ = os.Stdout.Write(out)
	_, _ = os.Stdout.Write([]byte("\n"))
	return 0
}
