package guard

import (
	"fmt"
	"sort"
	"strings"
)

// A host is the agent whose hook dialect this run speaks.  Only the tool names
// and the shape of the reply differ between agents.
//
// Named by --host rather than sniffed: the wrong dialect fails open, because a
// document the host does not understand is a command it runs unredacted.
type host struct {
	name string

	// shellTools name the tools this host runs commands through; anything else
	// is left alone.  wrapTool is the one whose input is rewritten; Claude Code's
	// second tool reads a running command's buffer, which is recognised so it can
	// be skipped deliberately.
	shellTools []string
	wrapTool   string

	// deny refuses the command.  The reason reaches the model, not the operator.
	deny func(reason string) map[string]any

	// rewrite replaces the tool input, and is handed every field the payload
	// carried rather than only the command.
	rewrite func(updated map[string]any) map[string]any
}

const rewriteReason = "faramir: output redacted; the deny list is what refuses a command"

var hosts = map[string]*host{
	// The allow is load-bearing: a rewritten command matches no permission rule,
	// so without it every command would prompt with nothing able to pre-approve.
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

	// Gemini CLI puts the refusal at the top level and has no allow to return,
	// so its own prompts are unaffected.  tool_input merges over the model's
	// arguments rather than replacing them, so one shape serves both hosts.
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

	// opencode and Kilo Code extend through in-process plugins rather than a
	// hook that runs a program, so the plugin faramir installs applies the
	// decision itself.  Two names for one contract today, so a divergence has
	// somewhere to go.
	"opencode": pluginHost("opencode"),
	"kilocode": pluginHost("kilocode"),
}

// pluginHost is the dialect spoken to faramir's own plugin: "deny" with the
// reason, "rewrite" with the tool input, nothing at all for a call left alone.
// An unrecognised decision fails closed.
func pluginHost(name string) *host {
	return &host{
		name:       name,
		shellTools: []string{"bash"},
		wrapTool:   "bash",
		deny: func(reason string) map[string]any {
			return map[string]any{"decision": "deny", "reason": reason}
		},
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

// defaultHost is what an invocation naming none speaks, since guards installed
// before --host existed are registered without it.
const defaultHost = "claude"

// lookupHost resolves --host.  An unknown name is an error rather than a
// fallback, because the wrong dialect fails open.
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
