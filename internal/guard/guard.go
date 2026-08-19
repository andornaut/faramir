// Package guard is a PreToolUse hook, run as `faramir guard`: it denies Bash
// commands that would put a secret in the context, and rewrites the rest to run
// under the redactor.  Reads the hook payload on stdin, writes a decision on
// stdout.  It is not the security boundary; see docs/design.md.
package guard

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/config"
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

// The command alternations the path rules share, named so configDirRules can
// build the same rules for a path known only at run time.  Readers carry
// interpreters and copiers as well as pagers: reading a key with python, or
// copying it somewhere unmatched and reading it there, is the same disclosure.
// "sed" is a writer only; "grep" is neither, so naming a .env file in a search
// is not refused.
const (
	readCommands = `\b(?-i:cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|` +
		`hexdump|uuencode|rev|tac|awk|cut|nl|dd|jq|yq|python3?|perl|ruby|tee|cp|` +
		`tar|scp|rsync)\b`
	writeCommands = `\b(?-i:rm|shred|truncate|mv|cp|tee|dd|sed|chmod|chown|chgrp|` +
		`setfacl|ln)\b`
)

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
	// same secrets and is readable by the agent's uid.  "[^|]*" stops at the
	// first pipe; "[\s/=]\.env" keeps faramir.env (refs, no values) out.
	readCommands + `[^|]*` +
		`(age\.key|sops/age|id_(rsa|dsa|ecdsa|ed25519)|\.config/faramir\b|/etc/faramir|/etc/faramir/secrets|/var/log/faramir)`,
	`\b(?-i:cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|hexdump|uuencode|rev|tac)\b[^|]*` +
		`(vault\.|secrets?\.(ya?ml|json|toml|env|ini|conf|txt|enc|gpg)\b|credentials\b|\.pem\b|` +
		`[\s/=]\.env(\.(local|development|production|test|staging))?([\s"']|$))`,
	`\bfind\b.*-name.*(age\.key|\.env|id_(rsa|dsa|ecdsa|ed25519))`,
	// Writes to faramir's own files.  The redirect rule matches the target word
	// only, so a heredoc mentioning one of these paths is not a write to it.
	writeCommands + `[^|]*` +
		`(age\.key|sops/age|\.config/faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|/usr/local/bin/faramir\b|\.sops\.ya?ml|\.vault\b)`,
	`>\s*\S*(age\.key|sops/age|\.config/faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|/usr/local/bin/faramir\b|\.sops\.ya?ml)`,
	// The plugin and extension an enrolment installs, which are faramir's own
	// files.  The merged files (.claude/settings.json, .mcp.json, opencode.json,
	// kilo.json, .agents/mcp_config.json) are deliberately absent: they carry the
	// operator's own settings beside faramir's, so editing them is ordinary work,
	// and `faramir doctor` reports a registration that went missing.
	writeCommands + `[^|]*` +
		`(\.opencode/plugins/faramir\.js|\.kilo/plugin/faramir\.js|\.pi/extensions/faramir\.ts)`,
	`>\s*\S*(\.opencode/plugins/faramir\.js|\.kilo/plugin/faramir\.js|\.pi/extensions/faramir\.ts)`,
	// faramir under sudo, whichever subcommand.  Nothing an agent may run needs
	// root -- `run`, `redact`, `status` and `refs` all answer as the agent's own
	// account -- so a sudo here is a daemon, a decision that is the operator's, or
	// a change to the install.  Only sudo's own flags may precede the name.
	// Managing a unit is not this, so "systemctl restart faramir-keeper" stays
	// allowed, as does journalctl.
	`\bsudo\b(\s+-\S+)*\s+faramir\b`,
	// The same commands unprivileged.  They act on the install rather than through
	// it, so they are the operator's whether or not sudo is in front: refused here
	// so the agent is told that rather than meeting a permission error it will try
	// to work around.  Held to cli.OperatorOnly by a test.
	`\bfaramir[-\s]+(init|init-project|vault[ \t]+add|vault[ \t]+edit|vault[ \t]+ls|vault[ \t]+rm|recipient[ \t]+add|recipient[ \t]+rm|recipient[ \t]+ls|recipient[ \t]+reseal|link[ \t]+add|link[ \t]+rm|link[ \t]+ls|logs|escalations|approve|deny|doctor|reload|uninstall)\b`,
	`\bsudo\b.*-u\s+faramir`,
	// Refused for what it costs, not because it hides anything: the wrapper fails
	// closed, so a stopped broker withholds every command's output in every
	// enrolled tree at once.
	`\bsystemctl\b.*\b(stop|disable|mask|kill|edit)\b.*\bfaramir-`,
}

const advice = "Blocked: this command would put a credential (or an encrypted blob) into " +
	"the conversation, where it would be sent to the model provider.\n\n" +
	"Use the faramir_run tool instead: it runs the command as a separate uid " +
	"that holds no keys of its own, and returns output with secrets replaced by " +
	"«SECRET:ref» tokens. Secrets are named, never pasted:\n\n" +
	"    faramir_run(cmd=[\"printenv\", \"ROUTER_PW\"],\n" +
	"                env_refs={\"ROUTER_PW\": \"faramir://home/router/admin\"})\n\n" +
	"Call faramir_refs to see the available names. You do not need the " +
	"value of a secret to use it, and you will not be given one."

// adviceOperator is for a command that is the operator's to run.  The account
// this agent runs as could not have carried it out, so the refusal saves the
// detour of finding that out from a permission error.
const adviceOperator = "Blocked: this is an operator command. It acts on the faramir " +
	"install rather than through it, so it is refused to this shell whether or not " +
	"sudo is in front of it, and the account you run as could not carry it out " +
	"either.\n\nAsk the operator to run it in their own terminal.\n\nWhat you can " +
	"run: the faramir_run and faramir_refs tools, `faramir status`, and " +
	"`faramir redact`. Between them they say what secrets exist and run " +
	"commands that need them, which is the whole of what an agent needs faramir " +
	"for."

// adviceOwn is for the rules that are not about disclosure.  Acting on
// faramir's own files, accounts or units discloses nothing, and the disclosure
// advice would offer faramir_run as the way to proceed: a brokered command runs
// as an account with less reach rather than more.
const adviceOwn = "Blocked: this is faramir's own file, account or unit. Not " +
	"because the command would disclose anything, but because it would change or " +
	"stop what keeps credentials out of this conversation.\n\n" +
	"faramir_run is not a way round it: a brokered command runs as an account " +
	"with less reach than yours, not more.\n\n" +
	"If this is deliberate, it is the operator's to do. Say what you were trying " +
	"to achieve and let them decide."

// ownershipMarkers are the substrings that identify a pattern as being about
// faramir's own things rather than about disclosure.  Matched against the
// pattern's own text, which is the same string in the compiled fallback and in
// the shipped file.  A prefix of writeCommands rather than the constant, the
// shipped file carrying the expansion rather than the name.
var ownershipMarkers = []string{
	`(?-i:rm|shred|truncate`, // writeCommands: editing or destroying
	`>\s*\S*`,                // a redirect into one of those paths
	`\bsystemctl\b`,          // stopping or masking a unit
}

// operatorMarkers are the rules that refuse a command for being the operator's
// rather than for what it would disclose or change: a refusal offering
// faramir_run to somebody who ran `faramir doctor` names a remedy for a problem
// they do not have.
var operatorMarkers = []string{
	`\s+faramir\b`,         // any faramir subcommand under sudo
	`\bfaramir[-\s]+(init`, // the same set unprivileged
}

// adviceFor picks the explanation that matches why the command was refused.
// Unclassified means disclosure, which is the larger half and the safer
// default.
func adviceFor(pattern string) string {
	for _, marker := range operatorMarkers {
		if strings.Contains(pattern, marker) {
			return adviceOperator
		}
	}
	for _, marker := range ownershipMarkers {
		if strings.Contains(pattern, marker) {
			return adviceOwn
		}
	}
	return advice
}

type compiled struct {
	source string
	re     *regexp.Regexp
}

// configDir is where this host's config, secrets and keys actually are, taken
// from the same place the daemons take it, so an install moved with
// --config-dir moves what these rules refuse.
func configDir() string {
	path := os.Getenv("FARAMIR_CONFIG")
	if path == "" {
		path = config.DefaultConfigPath
	}
	return filepath.Dir(path)
}

// configDirRules refuses reads and writes of one directory, whatever it is
// called: the same three shapes the literal rules use, so a moved install is
// covered the way /etc/faramir is.
func configDirRules(dir string) []string {
	quoted := regexp.QuoteMeta(dir)
	return []string{
		readCommands + `[^|]*` + quoted,
		writeCommands + `[^|]*` + quoted,
		`>\s*\S*` + quoted,
	}
}

func loadPatterns() []compiled {
	raw := fallback
	// Only for a directory the literals do not already name: this runs on every
	// Bash call, and a duplicate would compile three more regexps each time.
	if dir := configDir(); dir != "" && dir != "/" && dir != filepath.Dir(config.DefaultConfigPath) {
		raw = append(slices.Clone(raw), configDirRules(dir)...)
	}
	if data, err := os.ReadFile(patternsFile()); err == nil {
		var lines []string
		for line := range strings.SplitSeq(string(data), "\n") {
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
	// The same object undecoded: a rewrite replaces the whole tool input, so every
	// field has to be handed back, not only the one it changed.
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
// put back by "$1"; the match stops at the first separator, so the rest of a
// chain is still scanned.  Subcommands are named rather than matched by shape,
// the daemons being subcommands of this binary too.
//
// cli.Agent rather than cli.Operator: the exemption is for the arguments that
// would otherwise trip the read rules, which is `run`'s inner command and
// `redact`'s text.
var faramirCall = regexp.MustCompile(
	`(^|[;&|\n])\s*faramir[ \t]+(` +
		sanctionAlternation(cli.Agent) + `)\b[^;&|\n]*`)

// sanctionAlternation renders subcommand names as one alternation.  A grouped
// command is named as two tokens, so the space between them becomes the
// whitespace a shell would accept: `vault edit` has to match `vault   edit` and
// must not match `vaultedit`.
func sanctionAlternation(names []string) string {
	out := make([]string, 0, len(names))
	for _, name := range names {
		out = append(out, strings.ReplaceAll(regexp.QuoteMeta(name), " ", `[ \t]+`))
	}
	return strings.Join(out, "|")
}

func decide(command string) (string, bool) {
	// No sudo exemption: every faramir subcommand under sudo is refused below, so
	// there is nothing whose arguments would need sparing.
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
	// Parsed before stdin is read, so running this by hand does not hang on a
	// payload.
	fs := flag.NewFlagSet("guard", flag.ContinueOnError)
	hostName := fs.String("host", "", "the agent whose hook dialect to speak")
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
		return 0
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return 0 // never block on a payload this does not understand
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
		return emit(activeHost.deny(adviceFor(pattern) + "\n\n(matched deny pattern: " + pattern + ")"))
	}

	// A deny list only covers what someone thought to name, so everything else is
	// rewritten to run under the redactor rather than refused.  Exit status and
	// both streams are preserved; known values come back as tokens.
	wrapped, ok := wrap(activeHost, command, &p)
	if !ok {
		return 0
	}
	// Every field back, with only "command" changed.
	updated := map[string]any{}
	maps.Copy(updated, p.RawInput)
	updated["command"] = wrapped

	// The rewrite approves as well as rewrites: a wrapper that redacts output
	// cannot be allow-listed, the permission matcher refusing rules naming source,
	// eval or a compound statement, so "ask" would prompt on every command with no
	// rule able to pre-approve any of it.  For Bash, the deny list above replaces
	// the permission prompt.
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
// A prefix test, not a match anywhere, which would leave whatever is chained
// after it unwrapped.  A command merely piping into the redactor is not covered
// either: a pipe carries stdout and leaves stderr unredacted.
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
// trailing "&&" is not this.  Newlines count as trailing space, Go's $ being
// end of text rather than end of line.
var backgrounded = regexp.MustCompile(`(^|[^&])&[ \t\r\n]*$`)

// wrap rewrites a shell command so its output is redacted.  It sources a script
// rather than piping because the agent's shell persists between tool calls, so
// the command must not run in a child; see docs/design.md.  Not applied to
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
	}

	// One simple command rather than a compound statement, so the rewritten text
	// stays one word and one argument for whatever reads it next.  Quoted for
	// exactly one round trip through the sourced script's eval; see
	// agent/hooks/wrap.sh.
	return "source " + wrapScript() + " " + shellQuote(command), true
}

// stripTrailingAmp removes the trailing "&" that backgrounded matched, and the
// space around it.  Only the last one: an inner "a & b &" keeps its first,
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
