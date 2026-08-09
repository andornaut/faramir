// Package guard is a PreToolUse hook, run as `faramir guard`: it denies Bash
// commands that would put a secret in the context, and rewrites the rest to run
// under the redactor.  Reads the hook payload on stdin, writes a decision on
// stdout.  It is not the security boundary; see docs/design.md.
package guard

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/version"
)

// wrapScript is the shell fragment the rewrite sources.  Absolute: the
// rewritten string runs in the agent's working directory.
func wrapScript() string {
	if v := os.Getenv("FARAMIR_WRAP"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/wrap.sh"
}

// patternsFile is rendered per install, so it lives in libexec rather than
// under /etc/faramir.  Missing, the fallback list below is used.
func patternsFile() string {
	if v := os.Getenv("FARAMIR_DENY_PATTERNS"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/deny-patterns.txt"
}

// fallback is used if the patterns file is missing, so a broken install still
// fails closed.  Keep it in step with agent/hooks/deny-patterns.txt.
var fallback = []string{
	`ansible-vault\s+(view|decrypt|edit|rekey)`,
	`\bsops\s+(decrypt|-d|--decrypt|-i\s+.*-d)`,
	`\bsops\s+(-e|--encrypt|encrypt|set|unset|rotate|updatekeys)\b`,
	`\bage\s+(-d|--decrypt)`,
	// Bare age-keygen prints a private key; "-o FILE" writes it 0400 instead.
	`\bage-keygen\b(\s+-\S+)*\s*$`,
	`\bop\s+read\b`,
	`\bpass\s+show\b`,
	`\bgopass\s+show\b`,
	`\bvault\s+(read|kv\s+get)\b`,
	// Broad on purpose: nothing here can tell which name holds a secret.
	`\bprintenv\b`,
	// Matches only a bare dump in command position, so "env NAME=v cmd",
	// "env | grep FOO" and a filename ending in .env are not refused.
	`(^|[\s;&|(])env(\s+-\S+)*\s*$`,
	`\bset\s*$`,
	`\bdeclare\s+-x\b`,
	`/proc/\d+/environ`,
	`/proc/self/environ`,
	// Readers, encoders, interpreters and copiers pointed at key material.
	// "sops/age" is the operator's ~/.config/sops/age/keys.txt, which opens the
	// same store and is readable by the agent's uid.  "[^|]*" stops at the
	// first pipe; "[\s/=]\.env" keeps faramir.env (refs, no values) out.
	`\b(?-i:cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|hexdump|uuencode|rev|tac|` +
		`awk|cut|nl|dd|jq|yq|python3?|perl|ruby|tee|cp|tar|scp|rsync)\b[^|]*` +
		`(age\.key|sops/age|id_(rsa|dsa|ecdsa|ed25519)|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/var/log/faramir)`,
	`\b(?-i:cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|hexdump|uuencode|rev|tac)\b[^|]*` +
		`(vault\.|secrets?\.(ya?ml|json|toml|env|ini|conf|txt|enc|gpg)\b|credentials\b|\.pem\b|` +
		`[\s/=]\.env(\.(local|development|production|test|staging))?([\s"']|$))`,
	`\bfind\b.*-name.*(age\.key|\.env|id_(rsa|dsa|ecdsa|ed25519))`,
	// Writes to faramir's own files.  The redirect rule matches the target word
	// only, so a heredoc mentioning one of these paths is not a write to it.
	`\b(?-i:rm|shred|truncate|mv|cp|tee|dd|sed|chmod|chown|chgrp|setfacl|ln)\b[^|]*` +
		`(age\.key|sops/age|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|/usr/local/bin/faramir\b|\.sops\.ya?ml|\.vault\b)`,
	`>\s*\S*(age\.key|sops/age|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|/usr/local/bin/faramir\b|\.sops\.ya?ml)`,
	// Running a daemon, or running as its account, discloses; managing the unit
	// does not, so "systemctl restart faramir-keeper" stays allowed.  Only
	// sudo's own flags may precede the executable name.  journalctl is absent:
	// the daemons log ref names and counts, never values.
	`\bsudo\b(\s+-\S+)*\s+faramir[-\s]+(broker|keeper|exec|mcp|guard)\b`,
	`\bsudo\b.*-u\s+faramir`,
	// Taking the broker down turns redaction off silently: the wrapper fails
	// open when it cannot be reached.
	`\bsystemctl\b.*\b(stop|disable|mask|kill|edit)\b.*\bfaramir-`,
}

const advice = "Blocked: this command would put a credential (or an encrypted blob) into " +
	"the conversation, where it would be sent to the model provider.\n\n" +
	"Use the faramir_run tool instead: it runs the command as a separate uid " +
	"that holds the keys and returns output with secrets replaced by " +
	"«SECRET:ref» tokens. Secrets are named, never pasted:\n\n" +
	"    faramir_run(cmd=[\"printenv\", \"ROUTER_PW\"],\n" +
	"                env_refs={\"ROUTER_PW\": \"secret://home/router/admin\"})\n\n" +
	"Call faramir_list_secrets to see the available names. You do not need the " +
	"value of a secret to use it, and you will not be given one."

type compiled struct {
	source string
	re     *regexp.Regexp
}

func loadPatterns() []compiled {
	raw := fallback
	if data, err := os.ReadFile(patternsFile()); err == nil {
		var lines []string
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(line)
			if line != "" && !strings.HasPrefix(line, "#") {
				lines = append(lines, line)
			}
		}
		if len(lines) > 0 {
			raw = lines
		}
	}

	out := make([]compiled, 0, len(raw))
	for _, pattern := range raw {
		re, err := regexp.Compile("(?i)" + pattern)
		if err != nil {
			continue // a typo in the list must not disable the whole hook
		}
		out = append(out, compiled{source: pattern, re: re})
	}
	return out
}

type payload struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		Command  string `json:"command"`
		Args     []any  `json:"args"`
		InBackgd bool   `json:"run_in_background"`
	} `json:"tool_input"`
	// The same object undecoded: a rewrite replaces the whole tool input, so
	// every field has to be handed back, not only the one it changed.
	RawInput map[string]any `json:"-"`
}

func commandOf(p *payload) string {
	parts := []string{}
	if p.ToolInput.Command != "" {
		parts = append(parts, p.ToolInput.Command)
	}
	// Some clients send argv arrays; check those too.
	for _, a := range p.ToolInput.Args {
		if s, ok := a.(string); ok && s != "" {
			parts = append(parts, s)
		}
	}
	return strings.Join(parts, " ")
}

// faramirCall matches a sanctioned faramir invocation so its own arguments are
// not scanned.  RE2 has no lookbehind, so the leading separator is captured and
// put back by "$1".  The match stops at the first separator, so the rest of a
// chain is still scanned.  Subcommands are named rather than matched by shape,
// because the daemons are subcommands of this binary too; one missing from
// cli.Operator merely has its arguments scanned.
var faramirCall = regexp.MustCompile(
	`(^|[;&|\n])\s*(sudo\s+)?faramir[ \t]+(` +
		strings.Join(cli.Operator, "|") + `)\b[^;&|\n]*`)

func decide(command string) (string, bool) {
	stripped := faramirCall.ReplaceAllString(command, "$1")
	for _, p := range loadPatterns() {
		if p.re.MatchString(stripped) {
			return p.source, true
		}
	}
	return "", false
}

// Run is the `faramir guard` subcommand.
func Run(args []string) int {
	// Before stdin is read, so running this by hand does not hang on a payload.
	hostName := ""
	for i, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("faramir " + version.Version)
			return 0
		}
		if name, ok := strings.CutPrefix(arg, "--host="); ok {
			hostName = name
		} else if arg == "--host" && i+1 < len(args) {
			hostName = args[i+1]
		}
	}
	// Also before stdin: an unknown host is a misregistration, and every command
	// would otherwise be answered in a dialect the agent ignores.
	activeHost, err := lookupHost(hostName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir guard: %v\n", err)
		return 2
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 0
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return 0 // never block on a payload we do not understand
	}
	var raw struct {
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(data, &raw); err == nil {
		p.RawInput = raw.ToolInput
	}
	if !activeHost.handles(p.ToolName) {
		return 0
	}
	command := commandOf(&p)
	if command == "" {
		return 0
	}

	if pattern, denied := decide(command); denied {
		return emit(activeHost.deny(advice + "\n\n(matched deny pattern: " + pattern + ")"))
	}

	// A deny list only covers what someone thought to name, so everything else
	// is rewritten to run under the redactor rather than refused.  Exit status
	// and both streams are preserved; known values come back as tokens.
	wrapped, ok := wrap(activeHost, command, &p)
	if !ok {
		return 0
	}
	// Every field back, with only "command" changed.
	updated := map[string]any{}
	for k, v := range p.RawInput {
		updated[k] = v
	}
	updated["command"] = wrapped

	// The rewrite approves as well as rewrites: a wrapper that redacts output
	// cannot be allow-listed (the permission matcher refuses rules naming
	// source, eval or a compound statement), so returning "ask" would prompt on
	// every command with no rule able to pre-approve any of it.  For Bash, the
	// deny list above replaces the permission prompt.
	return emit(activeHost.rewrite(updated))
}

func emit(document map[string]any) int {
	out, err := json.Marshal(document)
	if err != nil {
		return 0
	}
	_, _ = os.Stdout.Write(out)
	_, _ = os.Stdout.Write([]byte("\n"))
	return 0
}

// isWrapped reports whether this command is one the rewrite already produced.
// A prefix test, not a match anywhere: a match anywhere would leave whatever is
// chained after it unwrapped.  A command merely piping into the redactor is not
// covered either, because a pipe carries stdout and leaves stderr unredacted;
// wrapping it costs one idempotent extra pass.
func isWrapped(command string) bool {
	trimmed := strings.TrimSpace(command)
	for _, verb := range []string{"source ", ". "} {
		if strings.HasPrefix(trimmed, verb+wrapScript()+" ") {
			return true
		}
	}
	return false
}

// backgrounded matches a command ending by putting a job in the background,
// whose output arrives after the wrapper has read and deleted the file.  A
// trailing "&&" is not this.  Newlines count as trailing space, since Go's $ is
// end of text rather than end of line.
var backgrounded = regexp.MustCompile(`(^|[^&])&[ \t\r\n]*$`)

// wrap rewrites a shell command so its output is redacted.  See docs/design.md
// for why it sources a script rather than piping: the agent's shell persists
// between tool calls, so the command must not run in a child.
//
// Not applied to BashOutput, which reads a running command's buffer rather than
// starting one, nor to a command this rewrite already produced.
func wrap(h *host, command string, p *payload) (string, bool) {
	switch {
	case !h.wraps(p.ToolName):
		return "", false
	case strings.TrimSpace(command) == "":
		return "", false
	case isWrapped(command):
		return "", false
	// Both want output as it arrives, which buffering cannot give them.
	case backgrounded.MatchString(command) || p.ToolInput.InBackgd:
		return "", false
	}

	// One simple command, so a single "Bash(source:*)" rule can allow-list it;
	// a rewrite built from "{ ...; }" and ";" cannot be allow-listed at all.
	// Quoted for exactly one round trip through the sourced script's eval; see
	// agent/hooks/wrap.sh.
	return "source " + wrapScript() + " " + shellQuote(command), true
}

// shellQuote renders a string as one single-quoted shell word.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
