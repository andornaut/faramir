package guard

import (
	"fmt"
	"slices"
	"sort"
	"strings"
)

// A host is the agent whose hook dialect this run speaks; only the tool names
// and the shape of the reply differ between agents. Named by --host rather
// than sniffed: the wrong dialect fails open, a document the host does not
// understand being a command it runs unredacted.
type host struct {
	// shellTools name the tools this host runs commands through; anything else is
	// left alone. wrapTool is the one whose input is rewritten; Claude Code's
	// second tool reads a running command's buffer, recognised so it can be
	// skipped deliberately.
	shellTools []string
	wrapTool   string
	// streamsInPlace marks a host whose shell persists between calls and whose
	// runner takes a long command async and polls it: a plain command is
	// rewritten to --stream-state, which redacts live without a subshell, so an
	// export survives the call and a long build shows its output as it runs.
	streamsInPlace bool
	// anyShellTool takes every tool as one that runs a command. For faramir's own
	// plugin, which asks only about a call carrying a command string, so gating on
	// the name again would leave a renamed shell tool unguarded. A hook host
	// cannot do this, being asked about every tool.
	anyShellTool bool

	// decode reads this host's payload into the common shape. Claude Code and
	// faramir's own plugin send {tool_name, tool_input}; Antigravity sends
	// {toolCall: {name, args}} and keys the command differently inside it. Nil
	// takes the first shape.
	decode func(data []byte) (*payload, error)

	// commandKey is the key in the tool's input that carries the command, and
	// the one a rewrite changes.
	commandKey string

	// refusesPaths says a tool carrying a path rather than a command is checked
	// against the same deny list, rather than being left to whatever the host's
	// own permission rules do with it. For the agent whose permission lists are
	// its own state and cannot be written by an install, this is the only thing
	// that refuses a read.
	refusesPaths bool

	// patchTool names a tool whose input carries a patch envelope rather than a
	// shell command. The envelope is not a command: the tool applies it itself,
	// so there is nothing to route, and the files it writes are named in the
	// envelope's own headers rather than in an argument. Checked against the deny
	// list by those headers, and never rewritten -- a patch fed through the
	// wrapper is a patch that no longer applies.
	//
	// Codex's apply_patch is the case, and it is the only way that agent writes a
	// file: it has no rule file an install can put a path in, so without this
	// nothing refuses it one.
	patchTool string

	// runsInAgentCwd says this host starts the guard itself, from the directory
	// the agent is working in, so this process's working directory is the one a
	// relative path in a tool call is relative to and resolving one against it
	// names the file the call meant. A hook host runs the guard as a program of
	// its own and promises nothing about where: there the resolved form would be
	// a guess, and a guess refuses the wrong file as readily as the right one.
	//
	// A payload that carries the agent's working directory is used ahead of
	// either, that being the host saying where rather than this process guessing.
	runsInAgentCwd bool

	// mergesInput says the host merges what a rewrite hands back into the call's
	// own arguments rather than replacing them, so only the command goes back.
	// Handing back every field would be harmless where it replaces and is a
	// second copy of the arguments where it merges.
	mergesInput bool

	// deny refuses the command. The reason reaches the model, not the
	// operator.
	deny func(reason string) map[string]any

	// rewrite replaces the tool input, and is handed every field the payload
	// carried rather than only the command, unless mergesInput says otherwise.
	rewrite func(updated map[string]any) map[string]any
}

// commandField is the key this host's command arrives under, defaulted for the
// hosts that predate the field.
func (h *host) commandField() string {
	if h.commandKey == "" {
		return "command"
	}
	return h.commandKey
}

const rewriteReason = "faramir: output redacted; the deny list is what refuses a command"

// denyDecision is the word every host spells a refusal with. One constant, so a
// host added later cannot spell it differently and fail open.
const denyDecision = "deny"

// denyPlain is the refusal the plugin and Antigravity dialects share: the
// decision and the reason, nothing else.
func denyPlain(reason string) map[string]any {
	return map[string]any{"decision": denyDecision, "reason": reason}
}

var hosts = map[string]*host{
	"claude": claudeCodeHost(),
	// Codex speaks Claude Code's dialect, and differs in what it runs a command
	// through and in what it has to fall back on.
	"codex": codexHost(),

	// opencode and Kilo Code extend through in-process plugins rather than a hook
	// that runs a program, so the plugin faramir installs applies the decision
	// itself. Two names for one contract, so a divergence has somewhere to go.
	"opencode": pluginHost(),
	// pi speaks the same dialect: its extension turns a deny into a blocked tool
	// call and a rewrite into a mutation of the call's own input.
	"pi":       pluginHost(),
	"kilocode": pluginHost(),

	// The Antigravity family: the CLI and the IDE ship one hook contract and one
	// language server between them, so they speak one dialect under two names,
	// the way the plugin hosts do. Named separately because the enrolments
	// differ: the CLI takes account-wide deny rules and the IDE has nowhere to
	// put any.
	"agy":         antigravityHost(),
	"antigravity": antigravityHost(),
}

// hookDecision is the dialect Claude Code and Codex share: the payload names
// the tool and flattens its input beside it, a decision goes back under
// hookSpecificOutput, and a rewrite is updatedInput, which replaces the call's
// arguments with what it carries.
//
// The allow is load-bearing on both: a rewritten command matches no permission
// rule, so without it every command would prompt with nothing able to
// pre-approve. It is not a substitute for one.
func hookDecision() *host {
	return &host{
		wrapTool: bashTool,
		deny: func(reason string) map[string]any {
			return map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       denyDecision,
				"permissionDecisionReason": reason,
			}}
		},
		rewrite: func(updated map[string]any) map[string]any {
			return map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "allow",
				"permissionDecisionReason": rewriteReason,
				"updatedInput":             updated,
			}}
		},
	}
}

// bashTool is the tool both hosts speaking that dialect run shell commands
// through. Codex's own tool is not called this internally; the name it puts in
// a hook payload is.
const bashTool = "Bash"

// claudeCodeHost adds the second tool Claude Code names: BashOutput reads a
// running command's buffer, recognised so it can be skipped deliberately.
func claudeCodeHost() *host {
	h := hookDecision()
	h.shellTools = []string{bashTool, "BashOutput"}
	return h
}

// codexHost is Codex, which reads a file by running one of the shell's own
// readers and writes one through apply_patch. So the command guard covers every
// read it makes, and the patch tool is the whole of what it writes with.
//
// Its file tools are refused here because there is nowhere else to refuse them:
// Codex's own `.rules` files are an exec policy, which decides commands and
// names no path, and its permission modes are its own state. Nothing an install
// writes can say "not this file", so the guard says it.
func codexHost() *host {
	h := hookDecision()
	h.shellTools = []string{bashTool}
	h.refusesPaths = true
	h.patchTool = applyPatchTool
	return h
}

// applyPatchTool is the tool Codex edits, creates, deletes and moves files
// with. Its input carries the patch rather than a command; see host.patchTool.
const applyPatchTool = "apply_patch"

// antigravityHost is the dialect Antigravity's PreToolUse hook speaks. Two
// things differ from Claude Code's beyond the spelling.
//
// The payload names the call rather than flattening it: {toolCall: {name,
// args}}, and the command sits at args.CommandLine.
//
// A rewrite is "overwrite", a shallow top-level merge into the call's own
// arguments, and the merged call is what runs. So only the command goes back:
// the rest of the arguments are already there, and Cwd among them is the
// directory the wrapper has to run in.
//
// The allow is load-bearing for the same reason it is on Claude Code: a
// rewritten command matches no permission rule. It is not a substitute for one.
// The permission check runs before the hook, so a call with no allow rule is
// refused and this is never asked.
func antigravityHost() *host {
	return &host{
		shellTools: []string{runCommandTool},
		wrapTool:   runCommandTool,
		decode:     decodeToolCall,
		// The IDE half of this family keeps its permission lists as its own state,
		// so no file an install writes refuses its file tools. Both halves are
		// registered for every tool and answer here, so the refusal lives here.
		refusesPaths:   true,
		commandKey:     "CommandLine",
		mergesInput:    true,
		streamsInPlace: true,
		deny:           denyPlain,
		rewrite: func(updated map[string]any) map[string]any {
			return map[string]any{
				"decision":  "allow",
				"reason":    rewriteReason,
				"overwrite": updated,
			}
		},
	}
}

// runCommandTool is the tool Antigravity runs shell commands through. Its
// browser and file tools carry no command and are left alone.
const runCommandTool = "run_command"

// pluginHost is the dialect spoken to faramir's own plugin: "deny" with the
// reason, "rewrite" with the tool input, nothing at all for a call left alone.
// An unrecognised decision fails closed.
func pluginHost() *host {
	return &host{
		anyShellTool: true,
		// These hosts' own rule files are prompts rather than refusals, so a path
		// is refused here. Asked of the guard rather than applied in the plugin:
		// the plugin decides nothing, and one implementation of a rule cannot
		// drift from another.
		refusesPaths: true,
		// The plugin and the extension run inside the agent's own process and
		// start the guard from there, so its working directory is the tree the
		// call was made in.
		runsInAgentCwd: true,
		deny:           denyPlain,
		rewrite: func(updated map[string]any) map[string]any {
			return map[string]any{"decision": "rewrite", "tool_input": updated}
		},
	}
}

// knownHosts names the dialects, sorted, for a stable error message.
func knownHosts() []string {
	out := make([]string, 0, len(hosts))
	for name := range hosts {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// defaultHost is what an invocation naming none speaks.
const defaultHost = "claude"

// lookupHost resolves --host. An unknown name is an error rather than a
// fallback, the wrong dialect failing open.
func lookupHost(name string) (*host, error) {
	if name == "" {
		name = defaultHost
	}
	h, ok := hosts[name]
	if !ok {
		return nil, fmt.Errorf("unknown --host %q; known hosts are %s",
			name, strings.Join(knownHosts(), ", "))
	}
	return h, nil
}

// wraps reports whether the named tool is the one whose input gets rewritten.
func (h *host) wraps(toolName string) bool {
	return h.anyShellTool || toolName == h.wrapTool
}

// handles reports whether this host runs shell commands through the named tool.
func (h *host) handles(toolName string) bool {
	if h.anyShellTool {
		return true
	}
	return slices.Contains(h.shellTools, toolName)
}
