package main

import "fmt"

// A host is the agent whose hook contract this run speaks.
//
// The guard reads one payload and writes one document.  What the payload means
// is the same everywhere -- a shell command about to run -- so everything
// between reading and writing is shared.  What differs is the name of the tool
// that runs a command, and the shape of the document that refuses or rewrites
// it.
//
// Named by --host rather than sniffed from the payload.  Which agent invoked
// the guard is a property of how it was enrolled, and enrolling is an explicit
// act; a guard that guessed would answer in the wrong dialect the first time
// two payloads looked alike, and answering in the wrong dialect fails open:
// a document the host does not understand is a command it runs unredacted.
type host struct {
	name string

	// shellTools name the tools this host runs commands through.  Anything else
	// is left alone, because only a command has output worth redacting.
	//
	// wrapTool is the one whose input is actually rewritten.  Claude Code has a
	// second tool that reads a running command's output, which is watched so the
	// guard can leave it alone deliberately rather than by not recognising it:
	// buffering output that is wanted while it streams would change what it
	// does.
	shellTools []string
	wrapTool   string

	// deny refuses the command.  The reason reaches the model rather than the
	// operator on both hosts, which is why its wording matters: it is the only
	// thing the agent can act on.
	deny func(reason string) map[string]any

	// rewrite replaces the tool input with one that redacts its own output.
	// It is handed every field the payload carried, not only the command, so a
	// timeout or a description the host sent is one it gets back.
	rewrite func(updated map[string]any) map[string]any
}

const rewriteReason = "faramir: output redacted; the deny list is what refuses a command"

var hosts = map[string]*host{
	// Claude Code states the decision in both directions, and the allow is
	// load-bearing rather than polite: a rewritten command matches no
	// permission rule, so without it every command would prompt and no rule
	// the operator could write would ever pre-approve one.  That is what makes
	// enrolling a project here cost its Bash prompts.
	"claude": {
		name:       "claude",
		shellTools: []string{"Bash", "BashOutput"},
		wrapTool:   "Bash",
		deny: func(reason string) map[string]any {
			return map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
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
	},

	// Gemini CLI puts the refusal at the top level and requires the reason with
	// it.  There is no allow to return: a hook that has not denied has not
	// approved either, so whatever the agent would have asked the operator, it
	// still asks.  Enrolling here removes no prompts, which also means it costs
	// none -- the trade Claude Code forces does not arise.
	//
	// tool_input merges with and overrides the model's arguments rather than
	// replacing them, so sending every field back is harmless here and required
	// on Claude.  One shape serves both.
	"gemini": {
		name:       "gemini",
		shellTools: []string{"run_shell_command"},
		wrapTool:   "run_shell_command",
		deny: func(reason string) map[string]any {
			return map[string]any{"decision": "deny", "reason": reason}
		},
		rewrite: func(updated map[string]any) map[string]any {
			return map[string]any{"hookSpecificOutput": map[string]any{
				"tool_input": updated,
			}}
		},
	},
}

// defaultHost is what an invocation that names none speaks.  Claude Code,
// because every guard installed before --host existed is registered without it.
const defaultHost = "claude"

// lookupHost resolves --host.  An unknown name is an error rather than a
// fallback: the wrong dialect fails open, so guessing is worse than refusing to
// start, which an operator sees the first time they run it.
func lookupHost(name string) (*host, error) {
	if name == "" {
		name = defaultHost
	}
	h, ok := hosts[name]
	if !ok {
		return nil, fmt.Errorf("unknown --host %q; known hosts are claude and gemini", name)
	}
	return h, nil
}

// wraps reports whether the named tool is the one whose input gets rewritten.
func (h *host) wraps(toolName string) bool { return toolName == h.wrapTool }

// handles reports whether this host runs shell commands through the named tool.
func (h *host) handles(toolName string) bool {
	for _, name := range h.shellTools {
		if name == toolName {
			return true
		}
	}
	return false
}
