package install

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// An agentTarget is one coding agent's enrolment: the files faramir writes into
// a tree so that agent runs its commands through the broker.
//
// Explicit rather than discovered: enrolling trades away every Bash prompt in
// the project on some agents.  Detection is only good for reporting what a tree
// already carries.
type agentTarget struct {
	name string

	// files are written relative to the tree.  A list rather than named fields,
	// since Claude Code splits its hook settings from its MCP registration and
	// Gemini CLI puts both in one file.
	files []agentFile

	// accountFiles go into the operator's home rather than a tree.  They refuse
	// to open key material wherever the agent is working and take nothing away,
	// so no project has to opt in.  Rendered, the paths refused being this
	// install's.
	accountFiles []agentFile

	// detect names the paths that mean this tree is already configured for this
	// agent.  Reported, never acted on.  Named rather than derived from files,
	// which are only what faramir writes; generic names stay out, a .mcp.json
	// naming no particular agent.
	detect []string

	// autoApprovesBash records what enrolling costs on this agent.  Claude Code:
	// a rewritten command matches no permission rule and the hook must approve
	// it, so every Bash prompt in the project is gone.  Gemini CLI: there is no
	// allow to return, so the prompts are untouched.
	autoApprovesBash bool

	// note is warned about on enrolment, for anything that is not the Bash
	// trade.
	note string
}

type agentFile struct {
	// path is relative to the tree.
	path string
	// asset is the embedded file to write.  An accountFiles asset is rendered as
	// a text/template whatever it is named, so agent/claude/settings.json carries
	// {{.ConfigDir}} without a .tmpl suffix; a files asset is written verbatim,
	// and none of those holds a marker.
	asset string
	// dirMode creates the parent when the path has one.
	mode os.FileMode
	// merge merges faramir's keys into an existing file rather than replacing
	// it, and requires the asset to be JSON.  True for every shared config;
	// false only where the path is faramir's own, so what is there is a previous
	// version of the same file.
	merge bool
}

var agentTargets = map[string]*agentTarget{
	"claude": {
		name: "claude",
		files: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.project.json", mode: 0o600, merge: true},
			{path: ".mcp.json", asset: "agent/claude/mcp.json", mode: 0o644, merge: true},
		},
		// Read and Edit rules only: Claude Code matches file permission checks
		// against Edit(path), which covers every file-editing tool, and a
		// Write(path) rule matches nothing.
		accountFiles: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.json", mode: 0o600, merge: true},
		},
		detect:           []string{".claude"},
		autoApprovesBash: true,
	},
	"gemini": {
		name: "gemini",
		files: []agentFile{
			// Hooks and mcpServers are both top-level keys of this one file.
			{path: ".gemini/settings.json", asset: "agent/gemini/settings.project.json", mode: 0o600, merge: true},
		},
		// Gemini refuses tool calls through a policy engine, and the
		// settings.json key for this is deprecated in favour of it.
		accountFiles: []agentFile{
			{path: ".gemini/policies/faramir.toml", asset: "agent/gemini/policies.toml.tmpl", mode: 0o600},
		},
		detect:           []string{".gemini"},
		autoApprovesBash: false,
	},

	// opencode and Kilo Code extend through in-process plugins rather than a
	// hook that runs a program, so what is installed is a JavaScript file that
	// calls `faramir guard` and applies what it answers.  The deny list and the
	// rewrite stay in the binary.
	//
	// A plugin directory needs no registration; the config file carries the MCP
	// server.
	"opencode": {
		name: "opencode",
		files: []agentFile{
			// faramir's own file: what is there is a previous version of this
			// plugin, so replacing it is the update.
			{path: ".opencode/plugins/faramir.js", asset: "agent/opencode/plugin.js", mode: 0o644},
			{path: "opencode.json", asset: "agent/opencode/opencode.json", mode: 0o644, merge: true},
		},
		// Deny rules only, and no catch-all.  The last matching wildcard wins
		// and the merge re-serialises with keys sorted, so an operator's rule
		// sorting after one of these takes effect.  Sorting puts a catch-all
		// first, and there is no default this is entitled to replace.
		accountFiles: []agentFile{
			{path: ".config/opencode/opencode.json", asset: "agent/opencode/permissions.json.tmpl", mode: 0o600, merge: true},
		},
		detect: []string{".opencode", "opencode.json", "opencode.jsonc"},
		// No approval is given or asked for: a plugin that has not thrown has
		// approved nothing, so the agent still prompts as it would have.
		autoApprovesBash: false,
		note:             pluginNote("opencode"),
	},

	"kilocode": {
		name: "kilocode",
		files: []agentFile{
			{path: ".kilo/plugin/faramir.js", asset: "agent/kilocode/plugin.js", mode: 0o644},
			// kilo.json rather than the docs' kilo.jsonc: a merge cannot
			// preserve the comments a .jsonc is kept for.  Both are read.
			{path: "kilo.json", asset: "agent/kilocode/kilo.json", mode: 0o644, merge: true},
		},
		// Deny rules only, and no catch-all, for the reason given on opencode's.
		accountFiles: []agentFile{
			{path: ".config/kilo/kilo.json", asset: "agent/kilocode/permissions.json.tmpl", mode: 0o600, merge: true},
		},
		// .kilocode is the legacy directory, still read.
		detect:           []string{".kilo", ".kilocode", "kilo.json", "kilo.jsonc"},
		autoApprovesBash: false,
		note:             pluginNote("Kilo Code"),
	},
}

// pluginNote is what an enrolment says about an agent that matches its bash
// permission rules against the command text.  Whether those rules run after the
// rewrite is documented by neither agent, so this states the symptom.
func pluginNote(agent string) string {
	const wrapper = "source /usr/local/libexec/faramir/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + " '<command>'`. Whether those " +
		"rules see the command or the rewrite is not documented: if commands start " +
		"prompting as the wrapper rather than as themselves, they see the rewrite, and a " +
		"rule naming `" + wrapper + " *` is what decides them from then on"
}

// defaultAgents is what an enrolment naming none writes.
var defaultAgents = []string{"claude"}

// KnownAgents lists the agents this can enrol, sorted.  Exported so the flag
// that takes one names them rather than carrying a copy.
func KnownAgents() []string { return knownAgents() }

// knownAgents lists the agents this can enrol, sorted for a stable error.
func knownAgents() []string {
	out := make([]string, 0, len(agentTargets))
	for name := range agentTargets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// resolveAgents turns --agent values into targets.  An unknown name is an error
// rather than a skip, which would leave a project the operator believes is
// covered.
func resolveAgents(names []string) ([]*agentTarget, error) {
	if len(names) == 0 {
		names = defaultAgents
	}
	seen := map[string]bool{}
	var out []*agentTarget
	for _, name := range names {
		target, ok := agentTargets[name]
		if !ok {
			return nil, fmt.Errorf("unknown --agent %q; known agents are %v",
				name, knownAgents())
		}
		if seen[name] {
			continue
		}
		seen[name] = true
		out = append(out, target)
	}
	return out, nil
}

// detectedAgents reports which known agents this tree already carries
// configuration for.  Reported, never acted on.
func detectedAgents(dir string) []string {
	var out []string
	for _, name := range knownAgents() {
		for _, path := range agentTargets[name].detect {
			if exists(filepath.Join(dir, path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}
