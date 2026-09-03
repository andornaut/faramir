package guard

import (
	"encoding/json"
	"errors"
	"maps"
	"path/filepath"
	"regexp"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
)

type payload struct {
	ToolName string `json:"tool_name"`
	// Cwd is the directory the agent is working in, where the host sends it. It
	// is what a relative path in a tool call is relative to, and taking the
	// host's word for it beats this process's own working directory, which a hook
	// host promises nothing about. Empty where the host sends none.
	Cwd       string `json:"cwd"`
	ToolInput struct {
		Command  string
		Args     []any
		InBackgd bool
	}
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
//
// The input is read as the object it is and the three fields this cares about
// are taken out of it by type, rather than being decoded into a struct that
// declares what each one must be. Every tool on a host shares one input
// namespace, so a field name means whatever the tool using it means: `args` is
// an argv array on the tools that run a command and a single string on a tool
// that takes one argument. A struct refuses the second at the decode, and a
// payload that will not decode is answered by refusing the call and telling the
// operator that nothing in the tree is redacted, which is a great deal to say
// about a tool whose input was perfectly well formed.
//
// Malformed JSON, a tool_input that is not an object, and a tool_name that is
// not a string still fail: those are the host's shape having changed, which is
// what that refusal is for.
func decodeToolInput(data []byte) (*payload, error) {
	var doc struct {
		ToolName string `json:"tool_name"`
		Cwd      string `json:"cwd"`
		// The input undecoded, which is also what a rewrite hands back so the
		// fields it did not change survive it.
		ToolInput map[string]any `json:"tool_input"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return nil, err
	}
	p := &payload{ToolName: doc.ToolName, Cwd: doc.Cwd, RawInput: doc.ToolInput}
	if command, ok := doc.ToolInput["command"].(string); ok {
		p.ToolInput.Command = command
	}
	p.ToolInput.Args = argsOf(doc.ToolInput["args"])
	if background, ok := doc.ToolInput["run_in_background"].(bool); ok {
		p.ToolInput.InBackgd = background
	}
	return p, nil
}

// argsOf is the words an input's "args" holds, in either spelling.
//
// A single string is one word rather than nothing: commandOf quotes what it is
// given, so the text still reaches the rules, and a tool argument naming a
// declared path is refused the way the same path in an argv array is. Any other
// shape holds no words to scan, and the paths inside it are still walked out of
// RawInput, which is what refuses a path whatever tool named it.
func argsOf(value any) []any {
	switch v := value.(type) {
	case []any:
		return v
	case string:
		return []any{v}
	}
	return nil
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
		return nil, errors.New("no toolCall.name: not the payload shape this host sends")
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
func refusedPath(cwd string, input map[string]any) (string, string, bool) {
	for _, candidate := range pathsIn(input, 0) {
		if !looksLikePath(candidate) {
			continue
		}
		if pattern, denied := refusedSpelling(cwd, candidate); denied {
			return candidate, pattern, true
		}
	}
	return "", "", false
}

// refusedSpelling asks the deny list about one path, in every spelling that
// names the same file and as a read and as a write. Split out because a patch
// envelope's headers are asked the same question by a different route.
func refusedSpelling(cwd, candidate string) (string, bool) {
	for _, spelling := range spellings(cwd, candidate) {
		for _, verb := range []string{"cat ", "tee "} {
			if pattern, denied := decide(verb + shellQuote(spelling)); denied {
				return pattern, true
			}
		}
	}
	return "", false
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
// documented spelling puts the envelope in a heredoc. denyrules.Segments reads a
// heredoc body as commands, quoted delimiter or not, so the deny list has
// already seen each header line as it was written and refused one that names a
// declared path. What that match does not reach is a header path in another
// spelling, relative to cwd or under "~", which refusedSpelling resolves and asks
// about again here.
//
// Only where a segment actually runs the tool. The alternative -- scanning
// every command for patch headers -- refuses a heredoc that writes
// documentation quoting one, which is ordinary work, and refusing it names the
// quoted line as though the file were being written.
func refusedPatchCommand(h *host, cwd, command string) (string, string, bool) {
	if h.patchTool == "" || !runsPatchTool(h.patchTool, command) {
		return "", "", false
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
func refusedPatchPath(cwd, patch string) (string, string, bool) {
	for _, header := range patchHeaders.FindAllStringSubmatch(patch, -1) {
		candidate := header[1]
		if candidate == "" {
			continue
		}
		if pattern, denied := refusedSpelling(cwd, candidate); denied {
			return candidate, pattern, true
		}
	}
	return "", "", false
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
