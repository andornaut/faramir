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

// wrapScript is the shell fragment the rewrite sources.  An absolute path
// because the rewritten string is handed back to a shell whose working
// directory is the agent's, and a source that silently fails to resolve would
// look exactly like a wrap that worked.
func wrapScript() string {
	if v := os.Getenv("FARAMIR_WRAP"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/wrap.sh"
}

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
	// Writing the store is the operator's, for the same reason reading it is:
	// the agent has no value to put in one and no way to check what it
	// replaced.
	`\bsops\s+(-e|--encrypt|encrypt|set|unset|rotate|updatekeys)\b`,
	`\bage\s+(-d|--decrypt)`,
	// Bare age-keygen prints a private key.  "-o FILE" writes it 0400 and
	// prints nothing, which is how a throwaway key is minted.
	`\bage-keygen\b(\s+-\S+)*\s*$`,
	`\bop\s+read\b`,
	`\bpass\s+show\b`,
	`\bgopass\s+show\b`,
	`\bvault\s+(read|kv\s+get)\b`,
	// printenv stays broad on purpose: "printenv PATH" is harmless and
	// "printenv ROUTER_PW" is not, and nothing here can tell which name is a
	// secret.
	`\bprintenv\b`,
	// The match ends after the flags, so "env NAME=value cmd" is ordinary
	// shell rather than a dump.  "env | grep FOO" narrows rather than dumps
	// and ends the match too.  "env" must sit in command position: "\benv\b"
	// also matched a filename ending in .env, so naming one at the end of a
	// line was refused as a dump.
	`(^|[\s;&|(])env(\s+-\S+)*\s*$`,
	`\bset\s*$`,
	`\bdeclare\s+-x\b`,
	`/proc/\d+/environ`,
	`/proc/self/environ`,
	// The faramir paths belong in this alternation rather than in rules of
	// their own: the store's filenames (/etc/faramir/secrets/<x>.sops.yml)
	// match none of the other alternatives, and a rule naming only
	// cat/less/more/head/tail leaves base64 and xxd free to dump a blob.
	// Standalone path rules also refused "ls /var/log/faramir", which reads
	// nothing.
	//
	// The key names are spelled out.  "id_[re]d?sa" read as though it covered
	// SSH keys: it matched id_rsa and id_dsa and missed id_ed25519, which is
	// what ssh-keygen has produced by default for years.
	//
	// "[^|]*" not ".*", so the rule stops at the first pipe rather than
	// refusing "cat notes.md | grep credentials".
	// "sops/age" is the age key an agent can actually reach: faramir's own age
	// key is keeper-owned 0400 wherever it sits, but the operator's
	// ~/.config/sops/age/keys.txt decrypts the same store and is readable by the
	// uid the agent runs as.
	// It matches none of the other alternatives, because the file is keys.txt
	// and "age\.key" wants a literal dot.
	//
	// The reader list carries interpreters and copiers as well as pagers:
	// reading a key with python, or copying it somewhere unmatched and reading
	// it there, is the same disclosure.  "sed" stays out of this rule, because
	// it edits far more often than it dumps; it appears in the write rule below
	// instead, where the paths are faramir's own and touching them at all is
	// wrong.  "grep" stays out so that naming a .env file in a search is not
	// refused.
	//
	// "[\s/=]\.env" rather than "\.env", so a file merely ending in those four
	// characters (faramir.env, which holds refs and no values) is not a dotenv.
	`\b(cat|less|more|head|tail|bat|xxd|od|strings|base64|base32|hexdump|uuencode|rev|tac|` +
		`awk|cut|nl|dd|jq|yq|python3?|perl|ruby|tee|cp|tar|scp|rsync)\b[^|]*` +
		`(vault|secrets?\.|[\s/=]\.env|age\.key|sops/age|id_(rsa|dsa|ecdsa|ed25519)|\.pem\b|credentials|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/var/log/faramir)`,
	`\bfind\b.*-name.*(age\.key|\.env|id_(rsa|dsa|ecdsa|ed25519))`,
	// Changing the broker's own files, rather than reading them.  The store is
	// writable by the agent's uid, and so is anything under a home; the hook's
	// patterns and binary decide what it refuses, so they are named here too.
	//
	// The redirect rule matches the target word only, not the rest of the line,
	// so that a heredoc writing documentation that mentions one of these paths
	// is not mistaken for a write to it.
	`\b(rm|shred|truncate|mv|cp|install|tee|dd|sed|chmod|chown|chgrp|setfacl|ln)\b[^|]*` +
		`(age\.key|sops/age|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|\.sops\.ya?ml|\.vault\b)`,
	`>\s*\S*(age\.key|sops/age|\.faramir\b|/etc/faramir|/etc/faramir/secrets|/usr/local/libexec/faramir|\.sops\.ya?ml)`,
	// journalctl is deliberately absent: the daemons log ref names and counts,
	// never values, so refusing it only stops the broker being debugged.
	// Running the daemon, or running as its account, discloses; managing the
	// unit does not.  One rule covering both denied "systemctl restart
	// faramir-keeper", which is what the docs tell an operator to run after
	// adding a secrets file.  The executable position is what separates them:
	// sudo's own flags may precede the name, nothing else may.
	`\bsudo\b(\s+-\S+)*\s+faramir-(broker|keeper|exec)\b`,
	`\bsudo\b.*-u\s+faramir`,
	// Stopping the broker is the exception: the wrapper fails open when it
	// cannot be reached, so taking it down turns redaction off everywhere
	// rather than breaking anything visibly.
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
	// The same object again, undecoded.  A rewrite has to hand back every field
	// it was given, not only the one it changed: updatedInput replaces the tool
	// input, so a timeout or a description dropped here is a timeout or a
	// description the tool never sees.
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
	hostName := ""
	for i, arg := range args {
		if arg == "--version" || arg == "-version" {
			fmt.Println("faramir-guard " + version.Version)
			return 0
		}
		if name, ok := strings.CutPrefix(arg, "--host="); ok {
			hostName = name
		} else if arg == "--host" && i+1 < len(args) {
			hostName = args[i+1]
		}
	}
	// Before stdin is read, like --version: an unknown host is a
	// misregistration, and the operator should see it the first time rather than
	// have every command silently answered in a dialect the agent ignores.
	activeHost, err := lookupHost(hostName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir-guard: %v\n", err)
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

	// Everything the deny list does not forbid still runs, and still prints
	// whatever it prints.  A deny list only covers what someone thought to name,
	// so it cannot be the whole defence against a credential reaching the
	// transcript by accident: the command that leaks one is usually a command
	// nobody would have thought to deny.
	//
	// So the command is rewritten to run under the redactor rather than
	// refused.  The child's exit status and both its streams are preserved; what
	// changes is that a value the broker knows about comes back as its token.
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

	// A rewritten command cannot be allow-listed, by design.  The permission
	// matcher refuses an allow rule against a compound statement ("Contains
	// compound_statement") and refuses one naming source or eval ("'source'
	// evaluates arguments as shell code) -- and a wrapper that redacts output
	// has to be one of those.  So a rewrite that claims nothing makes every
	// command prompt, with no rule that can ever stop it.
	//
	// The decision here is therefore explicit rather than incidental: for Bash,
	// the deny list above replaces the permission prompt.  It runs first, so a
	// forbidden command is still refused; what changes is that everything else
	// is approved by this hook rather than by a rule the operator wrote.
	//
	// There is no setting that returns "ask" instead.  It would prompt on every
	// command including ls, showing the rewritten text rather than what was
	// typed, with no rule able to pre-approve any of it, and it would strand an
	// unattended run on the first command with nobody to answer.
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

// alreadyWrapped keeps the rewrite idempotent, and keeps it off the redactor's
// own invocation.
//
// Anchored at a command position, the way faramirCall is: a bare "\s" would
// also match the words inside "echo 'run faramir redact next'", and a command
// that merely mentions the redactor would then be left unredacted.
var alreadyWrapped = regexp.MustCompile(`(^|[;&|\n])\s*(sudo\s+)?(\S*/)?faramir\s+redact\b`)

// isWrapped reports whether this command is one the rewrite already produced.
//
// The emitted form names the wrap script and never the redactor, so matching
// only alreadyWrapped would rewrite a rewritten command a second time.  Sourced
// twice in one shell, the inner copy reuses and then clears the outer's state,
// and the outer neither redacts nor deletes its temporary file.
func isWrapped(command string) bool {
	return alreadyWrapped.MatchString(command) ||
		strings.Contains(command, wrapScript())
}

// backgrounded matches a command that ends by putting a job in the background.
// Its output arrives after the group has returned, which is after the wrapper
// has read and deleted the file, so wrapping it would silently discard exactly
// the output the caller was waiting for.  A trailing "&&" is not this.
//
// Newlines count as trailing space.  Go's $ is end of text rather than end of
// line, so a multi-line command ending in "&\n" is backgrounded too.
var backgrounded = regexp.MustCompile(`(^|[^&])&[ \t\r\n]*$`)

// wrap rewrites a shell command so its output is redacted.
//
// The command stays in the caller's own shell, inside a brace group rather than
// a subshell or a pipeline.  That is the whole difficulty: the agent's shell
// persists between tool calls, so a wrapper that runs the command in a child
// loses every "cd", "export" and shell function it sets, and the next command
// runs somewhere else.  A brace group with a redirection changes neither.
//
// Output goes to a temporary file and is redacted after the group finishes,
// rather than through a pipe while it runs.  A pipeline would put the group in
// a subshell and lose the state again; process substitution keeps the state but
// races, because the shell moves on to the next command while the redactor is
// still writing, and whatever it had not written yet is lost.  Reading the file
// afterwards has neither problem, and the agent sees no difference: the tool
// returns a command's output in one piece anyway.
//
// The file is created 0600 by mktemp, under a tmpfs so the unredacted text is
// in memory rather than on a disk, and removed as soon as it has been read.
//
// Not applied to BashOutput, which reads an already-running command's buffer
// rather than starting one, and not to a command already under the redactor.
func wrap(h *host, command string, p *payload) (string, bool) {
	switch {
	case !h.wraps(p.ToolName):
		return "", false
	case strings.TrimSpace(command) == "":
		return "", false
	case isWrapped(command):
		return "", false
	// A backgrounded command outlives the group, and a run_in_background call
	// is polled through BashOutput while it runs.  Both want output as it
	// arrives, which is the one thing buffering cannot give them.
	case backgrounded.MatchString(command) || p.ToolInput.InBackgd:
		return "", false
	}

	// One simple command, not an inline compound statement.  The permission
	// matcher refuses to match an allow rule against a compound statement
	// ("Contains compound_statement"), so a rewrite built out of "{ ...; }" and
	// ";" cannot be allow-listed at all, whatever rule is written for it: every
	// command would prompt, forever. This form takes one "Bash(source:*)" rule.
	//
	// The shell that runs this is the caller's own, so the command is quoted
	// for one round trip through the sourced script's eval and no more.  See
	// agent/hooks/wrap.sh for why the rest of it is shaped the way it is.
	return "source " + wrapScript() + " " + shellQuote(command), true
}

// shellQuote renders a string as one single-quoted shell word.  The command is
// about to be re-parsed by the shell that sources the wrapper, so anything less
// exact changes what runs.
func shellQuote(s string) string {
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}
