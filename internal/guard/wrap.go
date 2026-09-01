package guard

import (
	"regexp"
	"strings"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/denyrules"
)

// faramirCall matches a sanctioned faramir invocation so its own arguments are
// not scanned. RE2 has no lookbehind, so the leading separator is captured and
// put back by the strip in decide; the match stops at the first separator, so
// the rest of a chain is still scanned. Subcommands are named rather than
// matched by shape, the daemons being subcommands of this binary too.
//
// cli.Agent rather than cli.Operator: the exemption is for faramir's own flags
// and refs, e.g. a ref in `run --env`, which would otherwise trip the read
// rules. It stops at a redirect operator (the `<>` in the class), so a redirect
// attached to the call is still scanned; and decide keeps `redact`'s child
// command after a `--`, since redact does not guard what it runs.
var faramirCall = regexp.MustCompile(
	`(^|[;&|\n])\s*faramir[ \t]+(` +
		denyrules.SubcommandAlternation(cli.Agent) + `)\b[^;&|\n<>]*`)

// childSeparator matches a standalone `--` token, the boundary before the child
// command of `run` and `redact`. A flag such as `--env` does not match: `--` is
// held to whitespace or an end on either side.
var childSeparator = regexp.MustCompile(`(^|\s)--(\s|$)`)

// stripFaramirCalls removes faramir's own invocations from a line before it is
// matched, so a ref name or a flag cannot read as the thing a rule refuses.
//
// No sudo exemption: every faramir subcommand under sudo is refused by a rule of
// its own, so there is nothing whose arguments would need sparing.
//
// The exemption spares faramir's own flags and refs, but keeps the leading
// separator, and for `redact` the child command after a `--`. Redact runs that
// child locally and filters only known values, so it must still be scanned. Run
// sends its child to the broker, which guards it there, so run's child stays
// exempt.
func stripFaramirCalls(command string) string {
	return faramirCall.ReplaceAllStringFunc(command, func(match string) string {
		sub := faramirCall.FindStringSubmatch(match)
		lead := sub[1]
		if sub[2] == "redact" {
			if loc := childSeparator.FindStringIndex(match); loc != nil {
				return lead + match[loc[0]:]
			}
		}
		return lead
	})
}

// withoutWrapper strips the leading `source <wrap.sh>` of a command the rewrite
// produced, so a rule can be asked whether it would still have matched without
// it.
//
// The wrapper lives in the libexec directory, which is declared, so the subject
// rule refuses any command naming it. That is every command the guard itself
// emits, and the form the instructions tell an agent to use, so it has to be
// left alone or the routing refuses its own output.
//
// The invocation, not the path. `rm <wrap.sh>` does not open with `source`, so
// nothing here strips it and the subject rule answers it: deleting the wrapper
// turns off redaction for every Bash command on the host, and the narrower
// exemption is what keeps that refused without a verb test to get wrong.
//
// Only at the start. A wrapper named later in a line is part of some other
// command, and that command is the one being asked about.
func withoutWrapper(command string) string {
	trimmed := strings.TrimLeft(command, " \t")
	for _, verb := range []string{"source ", ". "} {
		prefix := verb + wrapScript()
		if !strings.HasPrefix(trimmed, prefix) {
			continue
		}
		// The path has to end there. Without this, any name formed by appending
		// to the wrapper's own is exempted: `source <wrap.sh>.orig` is a
		// different file, and one inside a declared directory.
		rest := trimmed[len(prefix):]
		if rest != "" && rest[0] != ' ' && rest[0] != '\t' {
			continue
		}
		return rest
	}
	return command
}

// isWrapped reports whether this command is one the rewrite already produced.
// It must be a single command that is the wrap invocation: a command that only
// begins with one and chains more (`source wrap.sh 'x' && cat log`) is not
// wrapped, since the chained part would run unredacted. A trailing background
// `&` is the wrapper's own, so it is dropped before the command is split.
// Re-wrapping a chain is safe: the outer wrapper redacts the whole of it, and
// the rewrite is one quoted word that is stable on the next pass.
func isWrapped(command string) bool {
	trimmed := command
	if backgrounded.MatchString(trimmed) {
		trimmed = stripTrailingAmp(trimmed)
	}
	segments := denyrules.Segments(trimmed)
	if len(segments) != 1 {
		return false
	}
	only := strings.TrimSpace(segments[0])
	for _, verb := range []string{"source ", ". "} {
		if strings.HasPrefix(only, verb+wrapScript()+" ") {
			return true
		}
	}
	return false
}

// backgrounded matches a command ending by putting a job in the background,
// whose output arrives after the wrapper has read and deleted the file. A
// trailing "&&" is not this. Newlines count as trailing space, Go's $ being
// end of text rather than end of line.
var backgrounded = regexp.MustCompile(`(^|[^&])&[ \t\r\n]*$`)

// wrap rewrites a shell command so its output is redacted. It sources a script
// rather than piping because the agent's shell persists between tool calls, so
// the command must not run in a child; see docs/design.md. Not applied to
// BashOutput, which reads a running command's buffer rather than starting one,
// nor to a command this rewrite already produced.
func wrap(h *host, command string, p *payload) (string, bool) {
	switch {
	case !h.wraps(p.ToolName):
		return "", false
	case strings.TrimSpace(command) == "":
		return "", false
	case isWrapped(command):
		return "", false
	// A trailing "&" backgrounds the command in this same call; the "&" is on the
	// inner command, so it is stripped and re-added after the redactor.
	case backgrounded.MatchString(command):
		return "source " + wrapScript() + " --stream " +
			shellQuote(stripTrailingAmp(command)) + " &", true
	// run_in_background hands the whole command to the host to background; it
	// carries no "&" of its own, and the host reads its output later through
	// BashOutput, which sees what the redactor already passed.
	case p.ToolInput.InBackgd:
		return "source " + wrapScript() + " --stream " + shellQuote(command), true
	// Antigravity's run_command carries WaitMsBeforeAsync, after which the host
	// takes the command async and polls, so a captured long command showed
	// nothing until it exited. --stream-state redacts live with the eval kept in
	// the host's persistent shell, so an export survives the call as well.
	case h.streamsInPlace:
		return "source " + wrapScript() + " --stream-state " + shellQuote(command), true
	}

	// One simple command rather than a compound statement, so the rewritten text
	// stays one word and one argument for whatever reads it next. Quoted for
	// exactly one round trip through the sourced script's eval; see
	// agent/hooks/wrap.sh.
	return "source " + wrapScript() + " " + shellQuote(command), true
}

// stripTrailingAmp removes the trailing "&" that backgrounded matched, and the
// space around it. Only the last one: an inner "a & b &" keeps its first,
// which the eval backgrounds as the caller wrote it.
func stripTrailingAmp(command string) string {
	trimmed := strings.TrimRight(command, " \t\r\n")
	trimmed = strings.TrimSuffix(trimmed, "&")
	return strings.TrimRight(trimmed, " \t\r\n")
}

// shellQuote renders a string as one single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
