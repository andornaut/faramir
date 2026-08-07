// Command faramir-guard is a PreToolUse hook: it denies Bash commands that
// would put a secret in the context.
//
// This is an enforcement layer that also teaches.  A deterministic block plus a
// corrective message that names faramir_run changes behaviour far more reliably
// than prose in a config file, and unlike prose it still works if the model
// never reads CLAUDE.md.
//
// It is *not* the security boundary.  The agent uid cannot read the age key,
// the SSH keys, or the broker's /proc entries no matter what this hook does; if
// this binary were deleted, no secret could still reach the model provider.
// What the hook buys is a useful error instead of a confusing one, and a
// context window that does not fill up with encrypted blobs.
//
// Reads the hook payload on stdin, writes a PreToolUse decision on stdout.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"

	"github.com/andornaut/faramir/internal/version"
)

// patternsFile sits next to the hook rather than under /etc/faramir, so it
// travels with the binary that reads it: a hook installed without its patterns
// falls back to the list below, which is silently weaker than the shipped one.
func patternsFile() string {
	if v := os.Getenv("FARAMIR_DENY_PATTERNS"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/deny-patterns.txt"
}

// fallback is used if the patterns file is missing, so a broken install still
// fails closed.  Keep it in step with agent/hooks/deny-patterns.txt: a fallback
// weaker than the shipped list turns an install problem into a silent gap.
var fallback = []string{
	`ansible-vault\s+(view|decrypt|edit|rekey)`,
	`\bsops\s+(decrypt|-d|--decrypt|-i\s+.*-d)`,
	`\bage\s+(-d|--decrypt)`,
	`\bage-keygen\b`,
	`\bop\s+read\b`,
	`\bpass\s+show\b`,
	`\bgopass\s+show\b`,
	`\bvault\s+(read|kv\s+get)\b`,
	`\bprintenv\b`,
	// RE2 has no lookahead.  "[^|]*$" is an exact translation of Python's
	// "(?!.*\|)" here: env with no pipe anywhere after it.
	`\benv\b[^|]*$`,
	`\bset\s*$`,
	`\bdeclare\s+-x\b`,
	`/proc/\d+/environ`,
	`/proc/self/environ`,
	`\b(cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|hexdump|uuencode|rev|tac)\b.*` +
		`(vault|secrets?\.|\.env|age\.key|id_[re]d?sa|\.pem\b|credentials)`,
	`\b(cat|less|more|head|tail)\b.*/etc/faramir`,
	`\bfind\b.*-name.*(age\.key|\.env|id_rsa)`,
	`/var/log/faramir`,
	`\bjournalctl\b.*faramir`,
	`\bsudo\b.*(\bfaramir-(broker|keeper|exec)\b|-u\s+faramir)`,
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
		Command string `json:"command"`
		Args    []any  `json:"args"`
	} `json:"tool_input"`
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
// put back by the "$1" replacement instead.
//
// It stops at the first separator: anything past it is a separate command that
// the prefix does not sanction, and consuming it would let
// "faramir status; printenv" through untouched.  It also leaves the separator
// in place, so the next command in a chain still starts at one.
//
// The whitespace after "faramir" is required, not optional: "faramir\b" also
// matches the hyphen in "faramir-broker", so it sanctioned every
// "sudo faramir-keeper ..." and left the deny pattern for the daemons unable
// to fire.
var faramirCall = regexp.MustCompile(`(^|[;&|\n])\s*(sudo\s+)?faramir[ \t][^;&|\n]*`)

func decide(command string) (string, bool) {
	stripped := faramirCall.ReplaceAllString(command, "$1")
	for _, p := range loadPatterns() {
		if p.re.MatchString(stripped) {
			return p.source, true
		}
	}
	return "", false
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	// Checked before stdin is read: this is a hook, so an operator running it
	// by hand would otherwise get a process that sits waiting for a payload.
	for _, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("faramir-guard " + version.Version)
			return 0
		}
	}

	data, err := io.ReadAll(os.Stdin)
	if err != nil {
		return 0
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return 0 // never block on a payload we do not understand
	}
	if p.ToolName != "Bash" && p.ToolName != "BashOutput" {
		return 0
	}
	command := commandOf(&p)
	if command == "" {
		return 0
	}

	pattern, denied := decide(command)
	if !denied {
		return 0
	}

	out, err := json.Marshal(map[string]any{
		"hookSpecificOutput": map[string]any{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       "deny",
			"permissionDecisionReason": advice + "\n\n(matched deny pattern: " + pattern + ")",
		},
	})
	if err != nil {
		return 0
	}
	os.Stdout.Write(out)
	os.Stdout.Write([]byte("\n"))
	return 0
}
