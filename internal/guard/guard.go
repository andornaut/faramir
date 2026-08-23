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
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/cli"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/version"
)

// wrapScript is the shell fragment the rewrite sources. Absolute: the
// rewritten string runs in the agent's working directory.
func wrapScript() string {
	if v := os.Getenv("FARAMIR_WRAP"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/wrap.sh"
}

// patternsFile is rendered per install, so it lives in libexec rather than
// under /etc/faramir. Missing, the fallback list below is used.
func patternsFile() string {
	if v := os.Getenv("FARAMIR_DENY_PATTERNS"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/deny-patterns.txt"
}

// defaultInstallPaths is what an install at the compiled defaults occupies, in
// the order installDirs renders them.
//
// Written here rather than taken from internal/install, which cannot be
// imported: this package's own tests import that one, so the arrow only points
// one way. The rules generated from these have to equal the ones the shipped
// file carries at the same defaults, which TestTheFallbackMatchesTheShippedFile
// holds them to.
var defaultInstallPaths = []string{
	`/etc/faramir`,
	`/etc/faramir/secrets`,
	`/var/log/faramir`,
	`/usr/local/libexec/faramir`,
	`/var/lib/faramir-broker`,
	`/var/lib/faramir-keeper`,
	`/var/lib/faramir-exec`,
}

// fallback is used if the patterns file is missing, so a broken install still
// fails closed. Keep it in step with agent/hooks/deny-patterns.txt.
//
// A host whose config was moved by --config-dir is covered by configDirRules
// instead, which builds the same five rules for the path the config actually
// has. What this cannot carry either way is what the host declares: a
// [[secret.block]] entry is in the rendered file and nowhere else, so a host
// running on the fallback is a host running on faramir's own paths alone.
var fallback = fallbackPatterns()

// ActionPatterns is what the guard refuses for what a command does rather than
// for what it points at: decryption, another tool's secret store, and the
// commands that act on faramir's own install.
//
// Exported for `faramir block ls`, which lists them beside the entries this
// host declares. Nothing else could be asked what they are: an agent meets one
// as a refusal naming the rule that matched, never the set, so a rule that
// covers something reads exactly like one that does not.
//
// Not the path rules, which are generated per install from the same set the
// agents' own deny rules come from, and are already listed as the entries they
// were generated from.
func ActionPatterns() []string {
	return append([]string{}, fallbackOwn...)
}

// fallbackPatterns assembles the list in the shipped file's own order, which
// TestTheFallbackMatchesTheShippedFile compares line by line.
func fallbackPatterns() []string {
	subjects := make([]string, 0, len(defaultInstallPaths))
	for _, dir := range defaultInstallPaths {
		subjects = append(subjects, denyrules.Dir(dir))
	}
	out := append([]string{}, denyrules.For(subjects)...)
	return append(out, fallbackOwn...)
}

// No compiled-in verb rules. What a command does rather than what it points at
// is the operator's to declare, `faramir block add --command`, and a declared
// one is rendered into the shipped file rather than carried here: the fallback
// is what holds when that file cannot be read, and it can no more carry a
// declaration than it can carry a [[secret.block]] path.

// fallbackOwn is the rest of faramir's own: its binary, the files an enrolment
// installs, and the commands that act on the install rather than through it.
var fallbackOwn = []string{
	// The binary, named as one path rather than as its directory, or installing
	// any unrelated tool into /usr/local/bin would be refused.
	denyrules.WriteCommands + denyrules.ArgSpan + `/usr/local/bin/faramir\b`,
	`>\s*\S*/usr/local/bin/faramir\b`,
	// The plugin and extension an enrolment installs, which are faramir's own
	// files. The merged files (.claude/settings.json, .mcp.json, opencode.json,
	// kilo.json, .agents/mcp_config.json) are deliberately absent: they carry the
	// operator's own settings beside faramir's, so editing them is ordinary work,
	// and `faramir doctor` reports a registration that went missing.
	denyrules.WriteCommands + denyrules.ArgSpan +
		`(\.opencode/plugins/faramir\.js|\.kilo/plugin/faramir\.js|\.pi/extensions/faramir\.ts)`,
	`>\s*\S*(\.opencode/plugins/faramir\.js|\.kilo/plugin/faramir\.js|\.pi/extensions/faramir\.ts)`,
	// faramir under sudo, whichever subcommand. Nothing an agent may run needs
	// root -- `run`, `redact`, `status` and `refs` all answer as the agent's own
	// account -- so a sudo here is a daemon, a decision that is the operator's, or
	// a change to the install. Only sudo's own flags may precede the name.
	// Managing a unit is not this, so "systemctl restart faramir-keeper" stays
	// allowed, as does journalctl.
	`\bsudo\b(\s+-\S+)*\s+faramir\b`,
	// The same commands unprivileged. They act on the install rather than through
	// it, so they are the operator's whether or not sudo is in front: refused here
	// so the agent is told that rather than meeting a permission error it will try
	// to work around. Held to cli.OperatorOnly by a test.
	`\bfaramir[-\s]+(init|init-project|vault[ \t]+add|vault[ \t]+edit|vault[ \t]+ls|vault[ \t]+rm|reader[ \t]+add|reader[ \t]+rm|reader[ \t]+ls|reader[ \t]+reseal|link[ \t]+add|link[ \t]+rm|link[ \t]+ls|block[ \t]+add|block[ \t]+rm|block[ \t]+ls|logs|sudo[ \t]+ls|sudo[ \t]+watch|sudo[ \t]+approve|sudo[ \t]+reject|doctor|reload|uninstall)\b`,
	`\bsudo\b.*-u\s+faramir`,
	// Blocked for what it costs, not because it hides anything: the wrapper fails
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

// adviceOperator is for a command that is the operator's to run. The account
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

// adviceOwn is for the rules that are not about disclosure. Acting on
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

// adviceMarkers map a substring of a pattern to the explanation that pattern
// carries. Matched against the pattern's own text, which is the same string in
// the compiled fallback and in the shipped file.
//
// Ordered, first match winning: a faramir subcommand is the operator's before
// it is anything else. A refusal offering faramir_run to somebody who ran
// `faramir doctor` names a remedy for a problem they do not have.
var adviceMarkers = []struct {
	marker string
	advice string
	// ownPath is a pattern whose subjects are mixed: one rule carries this
	// install's own directories alongside the paths the operator declared or
	// linked, so the pattern cannot say whose path matched and the command has
	// to. Without this, `rm /srv/luks.key` is explained as faramir's own file.
	ownPath bool
}{
	{`\s+faramir\b`, adviceOperator, false},          // any faramir subcommand under sudo
	{`\bfaramir[-\s]+(init`, adviceOperator, false},  // the same set unprivileged
	{`\bsystemctl\b`, adviceOwn, false},              // stopping or masking a unit
	{`/usr/local/bin/faramir\b`, adviceOwn, false},   // the binary
	{`\.opencode/plugins/faramir`, adviceOwn, false}, // the plugin an enrolment writes
	// The head of denyrules.WriteCommands's word list rather than the constant,
	// the shipped file carrying the expansion rather than the name. The words
	// alone, not what wraps them: the group around them has changed shape once
	// already, and a marker carrying it silently stops matching when it does.
	{`rm|shred|truncate`, adviceOwn, true}, // editing or destroying a path
	{`>\s*\S*`, adviceOwn, true},           // a redirect into one
}

// adviceFor picks the explanation that matches why the command was refused.
// Unclassified means disclosure, which is the larger half and the safer
// default.
func adviceFor(pattern, command string) string {
	for _, m := range adviceMarkers {
		if !strings.Contains(pattern, m.marker) {
			continue
		}
		if m.ownPath && !namesOwn(command) {
			continue
		}
		return m.advice
	}
	return advice
}

// namesOwn reports whether the command names a directory belonging to this
// install, which is what separates a write faramir refuses to protect itself
// from a write to a secret the operator declared.
//
// The compiled defaults and this host's config directory. A log or libexec
// directory moved elsewhere reads as the operator's and gets the disclosure
// message, which is the safer of the two to be wrong about: it offers
// faramir_run, and a brokered command runs as an account with less reach.
func namesOwn(command string) bool {
	for _, dir := range append(append([]string{}, defaultInstallPaths...), configDir()) {
		if strings.Contains(command, dir) {
			return true
		}
	}
	return false
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
	return denyrules.For([]string{denyrules.DirUnder(guardHome(), dir)})
}

// guardHome is what a tilde in the command being judged stands for. This runs
// as the account the coding agent runs as, so $HOME is that account's own and
// is the home the command would have been expanded against.
func guardHome() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		return ""
	}
	return home
}

// named reports whether the list already carries a rule about this directory,
// which the rendered file does for the install it was rendered for.
//
// The subject as it would be generated, not the quoted path: a path is a
// substring of every path that starts the same way, so a config at
// /var/lib/faramir would have been read as already named by a rule about
// /var/lib/faramir-broker, and skipped. What that skips is the only cover a
// moved config has.
func named(raw []string, dir string) bool {
	// The subject as the rendered file writes it, which for a directory under a
	// home is the alternation of the spellings a shell expands to it. Asking for
	// the plain form would miss it and append the same five rules again, on
	// every Bash call.
	subject := denyrules.DirUnder(guardHome(), dir)
	for _, pattern := range raw {
		if strings.Contains(pattern, subject) {
			return true
		}
	}
	return false
}

func loadPatterns() []compiled {
	raw := fallback
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
	// After the file, not before it: the file replaces the list wholesale, so a
	// rule appended first was thrown away on every host that had one, which is
	// every installed host. It went unnoticed while the shipped file named
	// age.key and sops/age as literals, which covered a moved config by
	// accident; the subjects are generated per install now, so a config that
	// moved after the rules were rendered is covered by this and nothing else.
	//
	// Only for a directory the list does not already name: this runs on every
	// Bash call, and a duplicate would compile three more regexps each time.
	if dir := configDir(); dir != "" && dir != "/" && !named(raw, dir) {
		raw = append(slices.Clone(raw), configDirRules(dir)...)
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
// not scanned. RE2 has no lookbehind, so the leading separator is captured and
// put back by "$1"; the match stops at the first separator, so the rest of a
// chain is still scanned. Subcommands are named rather than matched by shape,
// the daemons being subcommands of this binary too.
//
// cli.Agent rather than cli.Operator: the exemption is for the arguments that
// would otherwise trip the read rules, which is `run`'s inner command and
// `redact`'s text.
var faramirCall = regexp.MustCompile(
	`(^|[;&|\n])\s*faramir[ \t]+(` +
		sanctionAlternation(cli.Agent) + `)\b[^;&|\n]*`)

// sanctionAlternation renders subcommand names as one alternation. A grouped
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
		if slices.ContainsFunc(spellings, p.re.MatchString) {
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
		// The same answer an unreadable payload gets below, and for the same
		// reason. Allowing here and denying there had the more broken case pass:
		// stdin that could not be read at all is no less a payload this cannot
		// guard than one that arrived and would not parse.
		return emit(activeHost.deny(unreadablePayload))
	}
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		// Fails closed, the way faramir's own plugin does on the same input. A
		// payload this cannot read is the host's shape having changed, and on the
		// hook that guards every Bash call the alternative is returning quietly
		// and leaving every command in every enrolled tree unredacted. Refusing
		// says so in the transcript, where somebody reads it.
		return emit(activeHost.deny(unreadablePayload))
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
		return emit(activeHost.deny(adviceFor(pattern, command) + "\n\n(matched deny pattern: " + pattern + ")"))
	}

	// A deny list only covers what someone thought to name, so everything else is
	// rewritten to run under the redactor rather than refused. Exit status and
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
	// rule able to pre-approve any of it. For Bash, the deny list above replaces
	// the permission prompt.
	return emit(activeHost.rewrite(updated))
}

// The two refusals that are about this hook rather than about the command. Both
// name what to do, because both reach the model rather than the operator: an
// agent that is told to stop and why can say so, where one that meets a silent
// refusal retries.
const (
	unreadablePayload = "Blocked: faramir's guard could not read this tool call, so it " +
		"could not decide whether the command discloses a credential, and the " +
		"command was not run.\n\nThis is not something to work around. Tell the " +
		"operator that `faramir guard` did not understand its input: the agent " +
		"and the install disagree about the shape of a hook payload, and until " +
		"that is fixed nothing this tree runs is redacted."
	noCommandString = "Blocked: faramir's guard was handed a shell tool call carrying no " +
		"command, so there was nothing to check and the call was not made.\n\n" +
		"Tell the operator: on a tool that runs commands this means the tool's " +
		"input is not the shape `faramir guard` reads."
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

// isWrapped reports whether this command is one the rewrite already produced.
// A prefix test, not a match anywhere, which would leave whatever is chained
// after it unwrapped. A command merely piping into the redactor is not covered
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
