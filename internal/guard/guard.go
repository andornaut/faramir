// Package guard is a PreToolUse hook, run as `faramir guard`: it denies Bash
// commands that would put a secret in the context, and rewrites the rest to run
// under the redactor. Reads the hook payload on stdin, writes a decision on
// stdout. It is not the security boundary; see docs/design.md.
package guard

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

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

// fallbackOwn is faramir's own: its binary, the files an enrolment installs,
// and the commands that act on the install rather than through it. Flattened
// from the catalogue's action rules, which is where they are spelled, in the
// shipped file's order: TestTheFallbackMatchesTheShippedFile compares the two
// line by line.
var fallbackOwn = denyrules.GuardRules(denyrules.ActionRules())

// ActionPatterns is what the guard refuses for what a command does rather than
// for what it points at: the commands that act on faramir's own install, and
// writes to the files an enrolment installs.
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
	// fallbackOwn first: a line can match both, and the rule that says something
	// more specific than "this path is in the blocks or the links" is the one
	// worth reporting.
	out := append([]string{}, fallbackOwn...)
	return append(out, denyrules.NamingAs(denyrules.KindOwn, subjects)...)
}

// No compiled-in verb rules. What a command does rather than what it points at
// is the operator's to declare, `faramir block add --command`, and a declared
// one is rendered into the shipped file rather than carried here: the fallback
// is what holds when that file cannot be read, and it can no more carry a
// declaration than it can carry a [[secret.block]] path.

// adviceOperator is for a command that is the operator's to run. The account
// this agent runs as could not have carried it out, so the refusal saves the
// detour of finding that out from a permission error.
const adviceOperator = "Blocked: this is an operator command. It acts on the faramir install rather than " +
	"through it, so it is refused whether or not sudo is in front, and your account " +
	"could not carry it out either.\n\nAsk the operator to run it. What you can run: " +
	"`faramir run`, `faramir refs`, `faramir status`, `faramir redact`, and the " +
	"commands that only describe the install: `faramir doctor`, `faramir block ls`, " +
	"`faramir link ls` and `faramir reader ls`.\n\nWhere `faramir doctor` says to run " +
	"it as root for the rest of an answer, that line is addressed to the operator. The " +
	"checks it names are the ones your account cannot make, and running the same command " +
	"under sudo is refused here."

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
const adviceNamed = ", so naming it is refused to your tools and to your shell, whatever the command would do with it."

const adviceRefs = "If the value answers a `faramir://` ref, `faramir refs` names it and " +
	"`faramir run --env NAME=faramir://<ref>` is the way to use it, which does not name the file."

// adviceRoute is the brokered route, for the entries where it is open. It is
// not always: the broker holds the same entries and refuses a command that
// would read the file. It is worth naming anyway, a command that only uses a
// credential being the ordinary case.
const adviceRoute = "\n\nA brokered command is answered differently: `faramir run` refuses the ones that " +
	"would read the file and allows the rest, so a command that only uses the credential may go " +
	"through there. " + adviceRefs

// adviceBlockedPath is for a path a [[secret.block]] entry names. The entry
// exists to refuse and nothing else, so removing it is the whole remedy.
const adviceBlockedPath = "Blocked: the operator blocked this path on this host" + adviceNamed + adviceRoute + "\n\nOtherwise this is the operator's to do, or to unblock with `faramir block rm`. " +
	"`faramir block ls` lists what they blocked."

// adviceLinkedPath is for the file a [[secret.link]] entry reads. Removing the
// entry takes the refusal back and the ref with it, so the ref is the thing to
// reach for first: it is what the link is for, and it answers without the file
// being named.
const adviceLinkedPath = "Blocked: a link reads this file on this host" + adviceNamed + adviceRoute +
	"\n\nThat ref is the point of the link, so prefer it to the file. `faramir link ls` lists the links " +
	"and the files they read. Removing one is the operator's to do, `faramir link rm`, and it takes " +
	"the ref away as well."

// adviceOwnPath is for a directory this install occupies. No entry declares
// these and no removal takes them back: they are rendered from the layout on
// every run, so a message offering a removal command would name a remedy that
// does not exist.
const adviceOwnPath = "Blocked: this is one of faramir's own directories" + adviceNamed + "\n\n" + adviceRefs +
	" A brokered command is no way round the directory itself: `faramir run` holds the same rules and " +
	"runs as an account with less reach than you.\n\nThere is no entry to remove either. These " +
	"are rendered from the install's layout on every run and are on neither `faramir block ls` nor " +
	"`faramir link ls`, so if this is deliberate it is the operator's to do."

// adviceDeclared is the safe default, for a rule no marker classified. It says
// what is true of any declared path and leaves the reader to find which kind
// applies, which is the most a message can do when the rule does not say.
//
// Disclosure rather than one of the narrower messages, because being wrong this
// way costs a detour and being wrong the other way tells an agent that the
// operator's own secret is faramir's file.
const adviceDeclared = "Blocked: this path is in the blocks or the links on this host" + adviceNamed + adviceRoute +
	"\n\nOtherwise this is the operator's to do, or to unblock: `faramir block rm` for a path they " +
	"blocked, `faramir link rm` for one a link reads. `faramir block ls` and `faramir link ls` say which it is, and " +
	"you may run both. The directories the install occupies are on neither list and are not " +
	"removable at all, being rendered from the layout on every run."

// adviceCommand is for a `[[secret.block]]` entry naming a command rather than a
// path. The remedy is the same shape and the subject is not: telling somebody
// who ran `op read` that a path is declared names nothing they typed.
const adviceCommand = "Blocked: this command is in the blocks on this host, so neither your shell nor a " +
	"brokered command may run it.\n\nThe words are matched where a command starts, so the same " +
	"words inside an argument or a path are left alone; a line of a heredoc is read as a command " +
	"and is not, so write a document with your editing tool rather than a shell heredoc. If the " +
	"work needs it, it is the operator's to do, or to unblock with `faramir block rm --command`."

// adviceOwn is for the rules that are not about disclosure. Acting on
// faramir's own files, accounts or units discloses nothing, and the disclosure
// advice would offer `faramir run` as the way to proceed: a brokered command
// runs as an account with less reach rather than more.
const adviceOwn = "Blocked: this is faramir's own file, account or unit. Not because it would disclose " +
	"anything, but because it would change or stop what keeps credentials out of this " +
	"conversation. `faramir run` is no way round it: a brokered command has less reach " +
	"than you.\n\nIf this is deliberate, it is the operator's to do."

// byKind is the message per catalogue kind, which is the same vocabulary the
// broker answers from. Two tables rather than one because the two tiers say
// different things: a brokered refusal talks about the account on the far side
// of it, and this one talks about your tools and your shell. What they share is
// what decides which sentence, so a kind cannot be answered here and forgotten
// there.
var byKind = map[denyrules.Kind]string{
	denyrules.KindOwn:       adviceOwnPath,
	denyrules.KindBlocked:   adviceBlockedPath,
	denyrules.KindLinked:    adviceLinkedPath,
	denyrules.KindCommand:   adviceCommand,
	denyrules.KindOperator:  adviceOperator,
	denyrules.KindOwnAction: adviceOwn,
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
	return denyrules.NamingAs(denyrules.KindOwn,
		[]string{denyrules.DirUnder(guardHome(), dir)})
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

// The compiled deny list is cached on the pattern strings it was built from, so
// decide does not recompile every regexp on each Bash call. A different patterns
// file or config dir yields a different key and recompiles. Guarded by a mutex
// because the hook may be exercised concurrently by a test.
var (
	patternCacheMu  sync.Mutex
	patternCacheKey string
	patternCacheVal []compiled
)

// rawFilePatterns reads the deny-pattern lines from the patterns file, dropping
// blanks and comments. Nil when the file is missing or holds no rule.
func rawFilePatterns() []string {
	data, err := os.ReadFile(patternsFile())
	if err != nil {
		return nil
	}
	var lines []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// withConfigDir appends the rules for a moved config dir. After the list, not
// before it: the file replaces the list wholesale, so a rule appended first is
// discarded, and the subjects are generated per install, so a config moved after
// the rules were rendered is covered by this and nothing else. Only for a
// directory the list does not already name, to avoid a duplicate rule.
func withConfigDir(raw []string) []string {
	if dir := configDir(); dir != "" && dir != "/" && !named(raw, dir) {
		return append(slices.Clone(raw), configDirRules(dir)...)
	}
	return raw
}

// compilePatterns compiles each pattern the way denyrules says one is read.
// complete is false when any line did not compile.
//
// Once per guard process, which is once per tool call: the cache above lives
// only as long as this one. Compilation is linear in the file's bytes at
// roughly 100ns each, so at 170 declared paths it is about 10ms and the
// matching that follows is 24us. What would cut it is not compiling the path
// rules at all where no literal in them appears in the command, which needs a
// list of those literals rendered beside the patterns: a second artifact an
// install can get out of step with the first, and a redesign rather than a
// change here.
func compilePatterns(raw []string) (out []compiled, complete bool) {
	complete = true
	out = make([]compiled, 0, len(raw))
	for _, pattern := range raw {
		re, err := denyrules.Compile(pattern)
		if err != nil {
			complete = false
			continue
		}
		out = append(out, compiled{source: pattern, re: re})
	}
	return out, complete
}

func loadPatterns() []compiled {
	fileLines := rawFilePatterns()
	usingFile := len(fileLines) > 0
	raw := fallback
	if usingFile {
		raw = fileLines
	}
	raw = withConfigDir(raw)

	key := strings.Join(raw, "\n")
	patternCacheMu.Lock()
	defer patternCacheMu.Unlock()
	if key == patternCacheKey && patternCacheVal != nil {
		return patternCacheVal
	}

	out, complete := compilePatterns(raw)
	if usingFile && !complete {
		// A bad line must not be dropped in silence: report it so the operator
		// knows a rule they wrote is not in force. The lines around it still stand.
		fmt.Fprintln(os.Stderr,
			"faramir guard: the deny-patterns file has an uncompilable line; skipping it")
	}
	if usingFile && len(out) == 0 {
		// Nothing in the file compiled, so running with an empty list would refuse
		// nothing. Fall back to the built-in rules, which still cover faramir's own
		// paths, so a wholly broken file leaves the guard no weaker than a missing
		// one does.
		out, _ = compilePatterns(withConfigDir(fallback))
	}
	patternCacheKey, patternCacheVal = key, out
	return out
}

type payload struct {
	ToolName string `json:"tool_name"`
	// Cwd is the directory the agent is working in, where the host sends it. It
	// is what a relative path in a tool call is relative to, and taking the
	// host's word for it beats this process's own working directory, which a hook
	// host promises nothing about. Empty where the host sends none.
	Cwd       string `json:"cwd"`
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
	// A command string is scanned as the shell reads it.
	if p.ToolInput.Command != "" {
		parts = append(parts, p.ToolInput.Command)
	}
	// An argv array is a list of literal words, not a shell string. Each element
	// is quoted so decide sees the words a real shell would pass: joined raw, an
	// element's own spaces, quotes or separators could re-split the line and carry
	// a read past a rule a faithful rendering catches.
	for _, a := range p.ToolInput.Args {
		if s, ok := a.(string); ok && s != "" {
			parts = append(parts, shellQuote(s))
		}
	}
	return strings.Join(parts, " ")
}

// decodeToolInput reads the shape Claude Code and faramir's own plugin send:
// the tool named at the top level and its input flattened beside it.
func decodeToolInput(data []byte) (*payload, error) {
	var p payload
	if err := json.Unmarshal(data, &p); err != nil {
		return nil, err
	}
	// The same object undecoded, so a rewrite that replaces the whole input can
	// hand back the fields it did not change.
	var raw struct {
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(data, &raw); err == nil {
		p.RawInput = raw.ToolInput
	}
	return &p, nil
}

// decodeToolCall reads Antigravity's shape, where the call is named rather than
// flattened and its command sits under a key of its own.
//
// A missing CommandLine leaves the command empty, which the caller answers the
// way it answers any wrapped tool arriving without one: it refuses. A tool this
// host runs no commands through never reaches that test, its name having
// survived the decode.
func decodeToolCall(data []byte) (*payload, error) {
	var doc struct {
		ToolCall struct {
			Name string         `json:"name"`
			Args map[string]any `json:"args"`
		} `json:"toolCall"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	// A payload carrying no tool name is not this host's shape. Any well-formed
	// JSON decodes into the struct above, so without this a single rename of
	// "toolCall" upstream would leave every call answered with silence, which the
	// host reads as a call to let through. Refused instead, the way an
	// unparseable payload is.
	if doc.ToolCall.Name == "" {
		return nil, errors.New("no toolCall.name: not this host's payload shape")
	}
	p := &payload{ToolName: doc.ToolCall.Name, RawInput: doc.ToolCall.Args}
	if command, ok := doc.ToolCall.Args["CommandLine"].(string); ok {
		p.ToolInput.Command = command
	}
	// The directory the call was made in, which this host keys inside the
	// arguments rather than beside them. Read here as well as kept in RawInput:
	// it is what a relative path in a file tool's arguments is relative to, and
	// this host is one that refuses paths, so without it a store named
	// "../secrets/db.sops.yml" from the tree beside it is asked about as written
	// and matched by nothing.
	if cwd, ok := doc.ToolCall.Args["Cwd"].(string); ok {
		p.Cwd = cwd
	}
	return p, nil
}

// pathAdvice is what a refused file tool is told. Its own wording rather than
// the command one's: nothing ran, so "this command" would name something that
// never happened, and the way through is the same either way.
const pathAdvice = "Blocked: %s is key material or one of faramir's own files, so this tool call " +
	"was not made.\n\nValues reach a command through the broker: use `faramir run`, and " +
	"`faramir refs` to see what exists."

// pathsIn is every string in a tool's input that could name a file, at any
// depth: a tool taking one path and a tool taking a list of them are the same
// question, and enumerating tool schemas is how one gets missed. The same walk
// the plugins do, in Go.
func pathsIn(value any, depth int) []string {
	if depth > 8 {
		return nil
	}
	switch v := value.(type) {
	case string:
		return []string{v}
	case []any:
		var out []string
		for _, item := range v {
			out = append(out, pathsIn(item, depth+1)...)
		}
		return out
	case map[string]any:
		// Sorted, so which of two refused paths is named does not depend on a map
		// iteration: a refusal that names a different file each time reads as two
		// different problems.
		var out []string
		for _, key := range slices.Sorted(maps.Keys(v)) {
			out = append(out, pathsIn(v[key], depth+1)...)
		}
		return out
	}
	return nil
}

// refusedPath is the first path in this tool call the deny list names.
//
// The list is the command one, asked about a read of that path rather than
// about the path alone. That is deliberate: the protected set is written once
// and rendered into the verbs a shell would use, so asking it this way covers
// the operator's own [[secret.block]] entries and this install's directories
// without a second list to keep in step. A list of its own is a list that
// drifts, and one that has drifted into matching nothing looks exactly like one
// that matches everything.
//
// What that borrows with it is a matcher built to find a path inside other
// text, which is right for a command line and wrong here: a tool's arguments
// carry prose as well as paths, and a sentence naming the age key is not a call
// to open it. So only an argument shaped like an absolute path is asked about,
// which is what a file tool is given and what a sentence is not.
//
// A relative path is resolved against cwd, and only where the caller had one to
// give: see host.runsInAgentCwd. Without it a relative path is asked as written,
// which matches only a rule spelled the same way, so a store named "../secrets"
// from the tree next to it would be read.
//
// Both verbs, because a file tool both reads and writes and the deny list
// spells the two separately: the plugin and extension an enrolment installs are
// refused to a write command alone, and those are the only thing refusing the
// file tools of the hosts asking here. A path protected either way refuses the
// call, whichever tool named it: an over-refusal here is a read of one of
// faramir's own files through an agent's file tool, and the operator's own
// tools are not this.
func refusedPath(cwd string, input map[string]any) (string, bool) {
	for _, candidate := range pathsIn(input, 0) {
		if !looksLikePath(candidate) {
			continue
		}
		if refusedSpelling(cwd, candidate) {
			return candidate, true
		}
	}
	return "", false
}

// refusedSpelling asks the deny list about one path, in every spelling that
// names the same file and as a read and as a write. Split out because a patch
// envelope's headers are asked the same question by a different route.
func refusedSpelling(cwd, candidate string) bool {
	for _, spelling := range spellings(cwd, candidate) {
		for _, verb := range []string{"cat ", "tee "} {
			if _, denied := decide(verb + shellQuote(spelling)); denied {
				return true
			}
		}
	}
	return false
}

// patchHeaders matches the file each header line of a patch envelope names.
// Codex's apply_patch carries the whole patch in the tool input's command, so
// the files it writes are named on these lines and nowhere else.
//
// Anchored per line, and the whole of the rest of the line is the path: a name
// may carry spaces, so the run-of-non-space test refusedPath uses is the wrong
// one here and a header line needs none of it. The grammar has already decided
// this is a path.
//
// The trailing class takes a carriage return as well. Go's `$` in multi-line
// mode matches before the newline and leaves a CRLF's "\r" on the capture, and
// a path rule is bounded at its right edge, so a CRLF envelope would name the
// age key and match no rule about it.
var patchHeaders = regexp.MustCompile(
	`(?m)^\*\*\*[ \t]+(?:Add File|Update File|Delete File|Move to):[ \t]*(.+?)[ \t\r]*$`)

// refusedPatchCommand is refusedPatchPath asked of a shell command rather than
// of the patch tool's own call. The tool is invocable from a shell, and the
// documented spelling puts the envelope in a quoted heredoc, whose body is data
// rather than commands: the deny list is matched against the segments, so the
// headers inside are never asked about. Every other heredoc write names its
// file on the opening line, which the list does see.
//
// Only where a segment actually runs the tool. The alternative -- scanning
// every command for patch headers -- refuses a heredoc that writes
// documentation quoting one, which is ordinary work, and refusing it names the
// quoted line as though the file were being written.
func refusedPatchCommand(h *host, cwd, command string) (string, bool) {
	if h.patchTool == "" || !runsPatchTool(h.patchTool, command) {
		return "", false
	}
	return refusedPatchPath(cwd, command)
}

// runsPatchTool reports whether any command on this line is the patch tool. The
// first word of a segment, by base name, so an absolute invocation counts and
// the tool named as an argument to something else does not.
func runsPatchTool(tool, command string) bool {
	for _, segment := range denyrules.Segments(command) {
		if filepath.Base(firstWord(segment)) == tool {
			return true
		}
	}
	return false
}

// firstWord is the program a segment runs: everything up to the first character
// that cannot be part of the name.
//
// A space is not the only thing that ends it. A shell needs no separator before
// a redirection, so `apply_patch<<'EOF'` and `apply_patch>out` name the same
// program as `apply_patch `, and a tab separates as well as a space. Cutting on
// a space alone left every one of those reading as a different program, which
// for the patch tool meant its envelope was never examined.
func firstWord(segment string) string {
	segment = strings.TrimSpace(segment)
	if i := strings.IndexAny(segment, " \t<>|&;"); i >= 0 {
		return segment[:i]
	}
	return segment
}

// refusedPatchPath is the first file a patch envelope names that the deny list
// refuses.
//
// Every header, not the first: a patch is a list of edits, and one that adds a
// README and replaces an age key is refused for the second.
func refusedPatchPath(cwd, patch string) (string, bool) {
	for _, header := range patchHeaders.FindAllStringSubmatch(patch, -1) {
		candidate := header[1]
		if candidate == "" {
			continue
		}
		if refusedSpelling(cwd, candidate) {
			return candidate, true
		}
	}
	return "", false
}

// spellings is the ways one argument names the same file: as given, with "~"
// expanded, resolved against cwd where there is one and the argument is
// relative, and with dot segments and doubled separators taken out.
//
// Each is a way past a literal rule. The paths this install names are rendered
// as literals, and a literal only ever matches itself, so "/home/op/./creds.txt"
// and "//home/op/creds.txt" name the refused file and match no rule about it.
// A "~" is the same problem in another spelling: the rules carry the operator's
// real home. A relative path is the same problem again, and the resolved form
// is what a rule naming an absolute path can match.
func spellings(cwd, candidate string) []string {
	out := []string{candidate}
	if home := guardHome(); home != "" && strings.HasPrefix(candidate, "~/") {
		out = append(out, home+candidate[1:])
	}
	if cwd != "" && !strings.HasPrefix(candidate, "/") && !strings.HasPrefix(candidate, "~/") {
		out = append(out, filepath.Join(cwd, candidate))
	}
	for _, form := range slices.Clone(out) {
		if cleaned := filepath.Clean(form); cleaned != form {
			out = append(out, cleaned)
		}
	}
	return out
}

// looksLikePath reports whether this argument is one a file tool was given
// rather than text that happens to mention a file.
//
// Two ways to qualify, because neither covers the other. A path may carry
// spaces, so anything absolute or under the home is asked about however it
// reads. And a name or a relative path carries no separator to anchor on but
// never carries a space either, so a run of non-space text is asked about too:
// that is what keeps a declared "credentials" and a "secrets/age.key" covered.
//
// What falls outside both is prose, which is the whole point: a sentence naming
// the age key is not a call to open it, and refusing one blocks ordinary work
// on a file that merely mentions a path.
//
// A newline rules a candidate out twice over: nothing names a file that way
// here, and one would end the synthesised command and leave the rest scanned as
// a second.
func looksLikePath(candidate string) bool {
	if candidate == "" || strings.ContainsAny(candidate, "\n\r") {
		return false
	}
	if strings.HasPrefix(candidate, "/") || strings.HasPrefix(candidate, "~/") {
		return true
	}
	return !strings.ContainsAny(candidate, " \t")
}

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
		if path, denied := refusedPatchPath(cwd, p.ToolInput.Command); denied {
			return emit(activeHost.deny(fmt.Sprintf(pathAdvice, path)))
		}
		return 0
	}
	// Before the tool gate: a file tool is one this host runs no commands
	// through, so gating on the name first would leave every read unexamined on
	// the host that has nothing else to refuse one.
	command := commandOf(p)
	if command == "" && activeHost.refusesPaths {
		if path, denied := refusedPath(cwd, p.RawInput); denied {
			// No pattern named. The list is asked about a read of this path, so the
			// pattern that answers is a reader-verb alternation, which describes how
			// the question was put rather than why the file is refused.
			return emit(activeHost.deny(fmt.Sprintf(pathAdvice, path)))
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
		note := "\n\n(matched deny pattern: " + shortPattern(pattern) + ")"
		if segment := matchingSegment(command, pattern); segment != "" {
			note = "\n\nOne command in the line matched, and the whole call is refused" +
				" because a hook answers for all of it. This is the command to change:" +
				"\n\n    " + shortSegment(segment) +
				"\n\n(matched deny pattern: " + shortPattern(pattern) + ")"
		}
		return emit(activeHost.deny(adviceFor(pattern) + note))
	}

	// The same question the patch branch above asks, of a command that runs the
	// patch tool itself: the documented way to invoke it from a shell is with the
	// envelope in a quoted heredoc, and a quoted heredoc body is data rather than
	// commands, so the list above never sees the headers. Every other heredoc
	// write names its file on the opening line, which the list does see; this is
	// the one that does not.
	if path, denied := refusedPatchCommand(activeHost, cwd, command); denied {
		return emit(activeHost.deny(fmt.Sprintf(pathAdvice, path)))
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
		"guard` did not understand its input: until that is fixed nothing this tree runs is " +
		"redacted."
	noCommandString = "Blocked: faramir's guard was handed a shell tool call carrying no command, so " +
		"there was nothing to check.\n\nTell the operator: the tool's input is not the " +
		"shape `faramir guard` reads."
	unreadablePatch = "Blocked: faramir's guard was handed a patch it could not read, so it could not " +
		"tell which files the patch writes.\n\nTell the operator: the patch tool's input is " +
		"not the shape `faramir guard` reads, and until that is fixed this tool could write " +
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
