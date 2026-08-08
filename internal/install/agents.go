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
// The list is explicit rather than discovered from the filesystem.  Enrolling
// is not free -- on some agents it trades away every Bash prompt in the project
// -- and a directory left behind by trying an agent once is not a decision to
// enrol it.  What detection is good for is saying "this tree has a .gemini, you
// did not ask for it", which is a report, not an action.
type agentTarget struct {
	name string

	// files are written relative to the tree.  Claude Code splits its hook
	// settings from its MCP registration; Gemini CLI puts both in one file.
	// Neither shape is more correct, so the descriptor carries a list rather
	// than two named fields.
	files []agentFile

	// accountFiles are written into the operator's home by `init --agent-config`
	// rather than into a tree.  They refuse to open key material wherever the
	// agent is working and take nothing away, so unlike the hook there is no
	// reason to make a project opt in.
	//
	// rendered, because the paths refused are this install's: naming the
	// compiled defaults would protect a directory that does not exist on a host
	// whose config and store were moved into a home.
	accountFiles []agentFile

	// autoApprovesBash records what enrolling costs on this agent, so the
	// warning a run prints is the truth for the agent it just enrolled.
	//
	// Claude Code: a rewritten command matches no permission rule, and the hook
	// must approve for the command to run at all, so every Bash prompt in the
	// project is gone.  Gemini CLI: there is no allow to return, so a hook that
	// has not denied has not approved either and the prompts are untouched.
	autoApprovesBash bool
}

type agentFile struct {
	// path is relative to the tree.
	path string
	// asset is the embedded file to write.
	asset string
	// dirMode creates the parent when the path has one.  Empty parents are the
	// tree itself, which already exists.
	mode os.FileMode
}

var agentTargets = map[string]*agentTarget{
	"claude": {
		name: "claude",
		files: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.project.json", mode: 0o600},
			{path: ".mcp.json", asset: "agent/claude/mcp.json", mode: 0o644},
		},
		accountFiles: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.json", mode: 0o600},
		},
		autoApprovesBash: true,
	},
	"gemini": {
		name: "gemini",
		files: []agentFile{
			// Hooks and mcpServers are both top-level keys of this one file.
			{path: ".gemini/settings.json", asset: "agent/gemini/settings.project.json", mode: 0o600},
		},
		// A .toml under policies/ rather than a key in settings.json: Gemini
		// refuses tool calls through a policy engine, and the settings key that
		// used to do this is deprecated in favour of it.
		accountFiles: []agentFile{
			{path: ".gemini/policies/faramir.toml", asset: "agent/gemini/policies.toml.tmpl", mode: 0o600},
		},
		autoApprovesBash: false,
	},
}

// defaultAgents is what an enrolment that names none writes.  Claude Code, so
// that a command with no --agent keeps doing what it did before the flag
// existed.
var defaultAgents = []string{"claude"}

// knownAgents lists the agents this can enrol, sorted so the error naming them
// reads the same every time.
func knownAgents() []string {
	out := make([]string, 0, len(agentTargets))
	for name := range agentTargets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// resolveAgents turns --agent values into targets.  An unknown name is an error
// rather than a skip: a run that enrolled nothing and said so in a line nobody
// read is a project the operator believes is covered and is not.
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

// detected reports which known agents this tree already carries a directory
// for, so a run can say what it did not enrol.  Reported, never acted on.
func detectedAgents(dir string) []string {
	var out []string
	for _, name := range knownAgents() {
		for _, file := range agentTargets[name].files {
			parent := filepath.Dir(file.path)
			if parent == "." {
				continue
			}
			if exists(filepath.Join(dir, parent)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}
