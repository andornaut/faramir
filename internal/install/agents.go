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

	// accountFiles are written into the operator's home by `init --agent`
	// rather than into a tree.  They refuse to open key material wherever the
	// agent is working and take nothing away, so unlike the hook there is no
	// reason to make a project opt in.
	//
	// rendered, because the paths refused are this install's: naming the
	// compiled defaults would protect a directory that does not exist on a host
	// whose config and store were moved into a home.
	accountFiles []agentFile

	// detect names the paths that mean this tree is already configured for this
	// agent, relative to it.  Reported, never acted on.
	//
	// Named rather than derived from files, which are the paths faramir writes:
	// an opencode project has a .opencode long before it has the plugin
	// directory faramir puts a file in, and a tree carrying an agent's
	// configuration is the thing worth reporting.  Generic names stay out: a
	// .mcp.json is not a decision to use any particular agent.
	detect []string

	// autoApprovesBash records what enrolling costs on this agent, so the
	// warning a run prints is the truth for the agent it just enrolled.
	//
	// Claude Code: a rewritten command matches no permission rule, and the hook
	// must approve for the command to run at all, so every Bash prompt in the
	// project is gone.  Gemini CLI: there is no allow to return, so a hook that
	// has not denied has not approved either and the prompts are untouched.
	autoApprovesBash bool

	// note is warned about on enrolment when this agent has something to say
	// that is not the Bash trade.  Empty on the agents that do not.
	note string
}

type agentFile struct {
	// path is relative to the tree.
	path string
	// asset is the embedded file to write.
	asset string
	// dirMode creates the parent when the path has one.  Empty parents are the
	// tree itself, which already exists.
	mode os.FileMode
	// merge says faramir's keys are merged into a file that is already there
	// instead of the file being replaced, and requires the asset to be JSON.
	//
	// True for every shared config: these hold hooks, MCP servers and
	// permission rules that are the project's or the operator's, and faramir
	// writes a few named keys among them.  False only where the path is
	// faramir's own, so what is there is a previous version of this same file
	// and replacing it is the update.
	merge bool
}

var agentTargets = map[string]*agentTarget{
	"claude": {
		name: "claude",
		files: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.project.json", mode: 0o600, merge: true},
			{path: ".mcp.json", asset: "agent/claude/mcp.json", mode: 0o644, merge: true},
		},
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
		// A .toml under policies/ rather than a key in settings.json: Gemini
		// refuses tool calls through a policy engine, and the settings key that
		// used to do this is deprecated in favour of it.
		accountFiles: []agentFile{
			{path: ".gemini/policies/faramir.toml", asset: "agent/gemini/policies.toml.tmpl", mode: 0o600},
		},
		detect:           []string{".gemini"},
		autoApprovesBash: false,
	},

	// opencode and Kilo Code extend through plugins loaded into the agent's own
	// process rather than through a hook that runs a program, so what is
	// installed here is a JavaScript file that calls `faramir guard` and applies
	// what it answers.  The deny list and the rewrite stay in the binary; the
	// plugin is the translation and nothing else.
	//
	// A plugin directory needs no registration: both agents load what they find
	// in it at startup.  What the config file carries is the MCP server, which
	// is how the agent reaches the broker at all.
	"opencode": {
		name: "opencode",
		files: []agentFile{
			// faramir's own file, so it is replaced rather than merged: what is
			// there is a previous version of this same plugin, and replacing it
			// is how a rewritten one takes effect.
			{path: ".opencode/plugins/faramir.js", asset: "agent/opencode/plugin.js", mode: 0o644},
			{path: "opencode.json", asset: "agent/opencode/opencode.json", mode: 0o644, merge: true},
		},
		// Deny rules only, and no catch-all.  These are wildcard patterns where
		// the last matching rule wins, and the merge re-serialises the file with
		// its keys sorted, so a rule of the operator's that sorts after one of
		// these and matches the same path is the one that takes effect.  Sorting
		// puts a catch-all first, which is the order the agent's own docs
		// recommend; writing one here would replace the operator's default with
		// faramir's, and there is no default this is entitled to loosen.
		accountFiles: []agentFile{
			{path: ".config/opencode/opencode.json", asset: "agent/opencode/permissions.json.tmpl", mode: 0o600, merge: true},
		},
		detect: []string{".opencode", "opencode.json", "opencode.jsonc"},
		// No approval is given and none is asked for: a plugin that has not
		// thrown has not approved anything, so whatever the agent would have
		// prompted about, it still does.  What the rewrite does to the rules
		// those prompts come from is the note below, which is a different
		// question from this one.
		autoApprovesBash: false,
		note:             pluginNote("opencode"),
	},

	"kilocode": {
		name: "kilocode",
		files: []agentFile{
			{path: ".kilo/plugin/faramir.js", asset: "agent/kilocode/plugin.js", mode: 0o644},
			// kilo.json rather than kilo.jsonc, which is the name the docs
			// prefer: this file is merged, and a merge cannot preserve the
			// comments a .jsonc is kept for.  Both are read.
			{path: "kilo.json", asset: "agent/kilocode/kilo.json", mode: 0o644, merge: true},
		},
		// Deny rules only, and no catch-all, for the reason given on opencode's.
		accountFiles: []agentFile{
			{path: ".config/kilo/kilo.json", asset: "agent/kilocode/permissions.json.tmpl", mode: 0o600, merge: true},
		},
		// .kilocode is the legacy directory, still read.  A tree carrying one is
		// a tree configured for this agent, which is what detection reports.
		detect:           []string{".kilo", ".kilocode", "kilo.json", "kilo.jsonc"},
		autoApprovesBash: false,
		note:             pluginNote("Kilo Code"),
	},
}

// pluginNote is what an enrolment says about an agent that matches its bash
// permission rules against the command text.
//
// The rewrite is what those rules now see, if they run after it, and whether
// they do is documented by neither agent.  Stated as the symptom rather than as
// a claim about the ordering: a command prompting as the wrapper rather than as
// itself is what an operator will actually see, and it answers the question in
// one run.
func pluginNote(agent string) string {
	const wrapper = "source /usr/local/libexec/faramir/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + " '<command>'`. Whether those " +
		"rules see the command or the rewrite is not documented: if commands start " +
		"prompting as the wrapper rather than as themselves, they see the rewrite, and a " +
		"rule naming `" + wrapper + " *` is what decides them from then on"
}

// defaultAgents is what an enrolment that names none writes.  Claude Code, so
// that a command with no --agent keeps doing what it did before the flag
// existed.
var defaultAgents = []string{"claude"}

// KnownAgents lists the agents this can enrol, sorted.  Exported so the flag
// that takes one names them rather than carrying a copy that goes stale.
func KnownAgents() []string { return knownAgents() }

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

// detectedAgents reports which known agents this tree already carries
// configuration for, so a run can say what it did not enrol.  Reported, never
// acted on.
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
