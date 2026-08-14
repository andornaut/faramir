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
// Configured for the agents that are there, or for the ones named.  Enrolling
// trades away every Bash prompt in the project on some agents, so what `auto`
// will not do is configure one nobody runs: naming it is what says to.
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
	// agent.  Named rather than derived from files, which are only what faramir
	// writes; generic names stay out, a .mcp.json naming no particular agent.
	detect []string

	// detectHome is the same question about the operator's home rather than a
	// tree, and a different answer: an agent keeps its per-project configuration
	// beside the project and its own under a home, and the two are not the same
	// paths.  opencode is the plain case -- opencode.json in a tree, and
	// .config/opencode in a home.
	//
	// faramir's own rule file counts as evidence here, which is deliberate: it
	// is what makes a second `init` refresh what the first one wrote instead of
	// deciding the agent is gone.
	detectHome []string

	// homeInstructions is the file this agent reads as prose wherever it is
	// working, relative to the operator's home, and is where `init` writes the
	// account-wide credentials section.  Its own path per agent, and not
	// derivable from detectHome: opencode keeps its config under
	// .config/opencode and reads AGENTS.md from there, pi keeps its under .pi
	// and reads .pi/agent/AGENTS.md, and Kilo Code reads every .md in a rules
	// directory rather than one named file.
	//
	// Written because the deny rules beside it hold wherever the agent works and
	// arrive at the model as a bare permission error.  A refusal with no reason
	// is what invites the workaround: another tool, an interpreter, a base64
	// pipe.  This is what makes the refusal legible, in the one file that is
	// read in a tree faramir has never been run in.
	homeInstructions string

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
	// asset is the embedded file to write.  Every asset is rendered as a
	// text/template whatever it is named: agent/claude/settings.json carries
	// {{.ConfigDir}} without a .tmpl suffix, and the paths the installed binary
	// and its libexec sit at are named once in the layout rather than written
	// into each file that has to exec one.  What each is rendered against
	// differs: accountFiles against the install Layout, files against the
	// per-target pluginData.
	asset string
	// mode is 0o640 throughout: an enrolled tree is shared with the client group,
	// so group-readable is what the rest of the tree is, and group-writable is
	// what these must never be.  .claude/settings.json names the PreToolUse hook
	// and the executor is in that group.
	//
	// It keeps the group from writing through the file, and not from replacing
	// it: unlink is a permission on the directory.  See sharetree.Options.Keep.
	mode os.FileMode
	// defaultExport renders a plugin as a default-exported { id, server } rather
	// than a named export.  The one thing the two plugin hosts disagree about.
	defaultExport bool
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
			{path: ".claude/settings.json", asset: "agent/claude/settings.project.json.tmpl", mode: 0o640, merge: true},
			{path: ".mcp.json", asset: "agent/claude/mcp.json.tmpl", mode: 0o640, merge: true},
		},
		// Read and Edit rules only: Claude Code matches file permission checks
		// against Edit(path), which covers every file-editing tool, and a
		// Write(path) rule matches nothing.
		accountFiles: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.json", mode: 0o640, merge: true},
		},
		detect:           []string{".claude"},
		detectHome:       []string{".claude", ".claude.json"},
		homeInstructions: ".claude/CLAUDE.md",
		autoApprovesBash: true,
	},
	"gemini": {
		name: "gemini",
		files: []agentFile{
			// Hooks and mcpServers are both top-level keys of this one file.
			{path: ".gemini/settings.json", asset: "agent/gemini/settings.project.json.tmpl", mode: 0o640, merge: true},
		},
		// Gemini refuses tool calls through a policy engine, and the
		// settings.json key for this is deprecated in favour of it.
		accountFiles: []agentFile{
			{path: ".gemini/policies/faramir.toml", asset: "agent/gemini/policies.toml.tmpl", mode: 0o640},
		},
		detect:           []string{".gemini"},
		detectHome:       []string{".gemini"},
		homeInstructions: ".gemini/GEMINI.md",
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
			{path: ".opencode/plugins/faramir.js", asset: "agent/plugin.js.tmpl", mode: 0o640},
			{path: "opencode.json", asset: "agent/mcp.local.json.tmpl", mode: 0o640, merge: true},
		},
		// Deny rules only, and no catch-all.  The last matching wildcard wins
		// and the merge re-serialises with keys sorted, so an operator's rule
		// sorting after one of these takes effect.  Sorting puts a catch-all
		// first, and there is no default this is entitled to replace.
		accountFiles: []agentFile{
			{path: ".config/opencode/opencode.json", asset: "agent/permissions.json.tmpl", mode: 0o640, merge: true},
		},
		detect:           []string{".opencode", "opencode.json", "opencode.jsonc"},
		detectHome:       []string{".config/opencode", ".local/share/opencode"},
		homeInstructions: ".config/opencode/AGENTS.md",
		// No approval is given or asked for: a plugin that has not thrown has
		// approved nothing, so the agent still prompts as it would have.
		autoApprovesBash: false,
		note:             pluginNote("opencode"),
	},

	// pi extends through a TypeScript module loaded from the project, once the
	// project is trusted.  No MCP ships with it, so that module registers the
	// tools the other hosts reach through a server, shelling out to the CLI: see
	// agent/pi/extension.ts.tmpl, whose tool definitions are rendered from
	// internal/mcp's list rather than written a second time.
	"pi": {
		name: "pi",
		files: []agentFile{
			{path: ".pi/extensions/faramir.ts", asset: "agent/pi/extension.ts.tmpl", mode: 0o640},
		},
		// Nothing account-wide: pi has no such file to write, so the deny rules
		// the other targets put in one are compiled into the extension instead,
		// from the same list.  It refuses a tool call carrying a command through
		// the guard, and one carrying a path against those rules.
		detect:     []string{".pi"},
		detectHome: []string{".pi"},
		// pi reads this one from under its own directory rather than beside a
		// config, and loads it for every project.
		homeInstructions: ".pi/agent/AGENTS.md",
		// The extension returns a refusal rather than approving anything, so the
		// agent prompts as it would have.
		autoApprovesBash: false,
		note:             pluginNote("pi"),
	},

	"kilocode": {
		name: "kilocode",
		files: []agentFile{
			{path: ".kilo/plugin/faramir.js", asset: "agent/plugin.js.tmpl", mode: 0o640, defaultExport: true},
			// kilo.json rather than the docs' kilo.jsonc: a merge cannot
			// preserve the comments a .jsonc is kept for.  Both are read.
			{path: "kilo.json", asset: "agent/mcp.local.json.tmpl", mode: 0o640, merge: true},
		},
		// Deny rules only, and no catch-all, for the reason given on opencode's.
		accountFiles: []agentFile{
			{path: ".config/kilo/kilo.json", asset: "agent/permissions.json.tmpl", mode: 0o640, merge: true},
		},
		// .kilocode is the legacy directory, still read.
		detect:     []string{".kilo", ".kilocode", "kilo.json", "kilo.jsonc"},
		detectHome: []string{".config/kilo", ".config/kilocode", ".kilocode"},
		// A file of faramir's own in the global rules directory, every .md in
		// which is loaded for every project.  Kilo Code has no single named home
		// instructions file to add a section to.
		homeInstructions: ".kilocode/rules/faramir.md",
		autoApprovesBash: false,
		note:             pluginNote("Kilo Code"),
	},
}

// writeAgentFiles writes one list of an agent's files under root, and reports
// whether it changed anything and what it wrote.
//
// One function for both commands: `init` writes the account-wide rules into a
// home and `init-project` the hook and the MCP registration into a tree, and
// what differs is which list, what each file is rendered against, and who ends
// up owning it.  Everything else was written twice, which is how the two came
// to disagree about when to create a parent directory.
//
// render is supplied by the caller, the two having different things to render
// against: the install layout for an account file, the target's own data for a
// tree's.
// inTree says which root this is.  A tree's files are group-owned so the client
// group can read what the hook and the MCP registration are written into, and a
// link out of the tree would carry that group to a file the enrolment was never
// pointed at.  A home's decide neither, so an existing file keeps its group and
// a link may land wherever the operator keeps their dotfiles.
func writeAgentFiles(fs fsys, root string, uid, gid int, dirMode os.FileMode,
	inTree bool, render func(agentFile) ([]byte, error),
	files []agentFile) (bool, []string, error) {
	changed := false
	var written []string
	for _, file := range files {
		path := filepath.Join(root, file.path)
		// Only created, never re-owned: the directory is the account's or the
		// project's.  With the operator's own group, not keep: `init` runs as
		// root, so a ~/.config that does not exist yet would be created
		// operator:root and break every other tool that keeps state there.
		// preflight refuses to create ConfigDir's parent for the same reason.
		//
		// Skipped where the file sits at the root, which has an owner already and
		// is not this command's to assert.
		if parent := filepath.Dir(path); parent != filepath.Clean(root) {
			if _, err := fs.ensureDir(parent, dirMode, uid, gid, false); err != nil {
				return changed, written, err
			}
		}
		// A link followed, the owner checked, and nothing there left to the write
		// below.  These are the operator's and the project's files, and both
		// commands run as root on a path the account the agent runs as can write.
		// See fsys.editedFile.
		bound := ""
		if inTree {
			bound = root
		}
		spot, err := fs.editedFile(path, uid, bound)
		if err != nil {
			return changed, written, fmt.Errorf("%s: %w", path, err)
		}
		data, err := render(file)
		if err != nil {
			spot.close()
			return changed, written, err
		}
		// Merged, not overwritten: the file is the operator's or the project's to
		// edit, and only the keys faramir writes are touched.  Through the merge
		// even with nothing to merge into, so the first write is byte-for-byte
		// what the second would produce.
		if file.merge {
			was, err := spot.read()
			if err != nil {
				spot.close()
				return changed, written, err
			}
			merged, err := mergeJSON(was, data)
			if err != nil {
				spot.close()
				return changed, written, fmt.Errorf("%s: %w", path, err)
			}
			data = merged
		}
		// Ownership is set on a file this creates and left alone on one that is
		// already there, editedFile having established that it is the operator's.
		// The group is asserted either way in a tree, where the client group has
		// to read them; in a home it decides nothing, and asserting it would be
		// one more thing a run changes without being asked to.
		//
		// The mode is asserted throughout, unlike the credentials section's: these
		// carry the hook, and group-writable is what they must never be.
		writeUID, writeGID := uid, gid
		if spot.info != nil {
			// Its own, read off the file: a write renames a new file over the
			// path, so anything not named here comes out owned by root.
			ownerUID, ownerGID := ownerOf(spot.info)
			writeUID = ownerUID
			if !inTree {
				writeGID = ownerGID
			}
		}
		made, err := fs.writeEdited(spot, data, file.mode, writeUID, writeGID)
		spot.close()
		if err != nil {
			return changed, written, err
		}
		changed = changed || made
		written = append(written, path)
	}
	return changed, written, nil
}

// pluginNote is what an enrolment says about an agent that matches its bash
// permission rules against the command text.  Whether those rules run after the
// rewrite is documented by neither agent, so this states the symptom.
func pluginNote(agent string) string {
	const wrapper = "source " + DefaultLibexecDir + "/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + " '<command>'`. Whether those " +
		"rules see the command or the rewrite is not documented: if commands start " +
		"prompting as the wrapper rather than as themselves, they see the rewrite, and a " +
		"rule naming `" + wrapper + " *` is what decides them from then on"
}

// AgentAuto is the --agent value that means "whichever ones are here", and the
// default on both commands.  A name alongside it is configured whether or not
// it is here, so `--agent auto --agent pi` reads as "what is installed, plus
// pi".
const AgentAuto = "auto"

// agentScope is where auto looks for evidence.  The two commands ask the same
// question of different places: `init` writes into the operator's home, and
// `init-project` into one tree.
type agentScope int

const (
	// scopeHome is the operator's home directory.
	scopeHome agentScope = iota
	// scopeTree is one working tree.
	scopeTree
)

func (t *agentTarget) markers(scope agentScope) []string {
	if scope == scopeHome {
		return t.detectHome
	}
	return t.detect
}

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

// resolveAgents turns --agent values into targets, resolving "auto" against
// what dir carries.  An unknown name is an error rather than a skip, which
// would leave an operator believing something is covered.
//
// Naming an agent is what makes it configured whether or not it is here; auto
// only ever adds what it finds.  So the two compose without a rule about which
// wins: the result is the union, and an operator who wants an agent configured
// ahead of installing it says so by name.
//
// Returned in a fixed order, so a report reads the same twice and a second run
// writes the same files in the same sequence.
func resolveAgents(names []string, scope agentScope, dir string) ([]*agentTarget, error) {
	if len(names) == 0 {
		names = []string{AgentAuto}
	}
	wanted := map[string]bool{}
	for _, name := range names {
		if name == AgentAuto {
			for _, found := range detectAgents(scope, dir) {
				wanted[found] = true
			}
			continue
		}
		if _, ok := agentTargets[name]; !ok {
			return nil, fmt.Errorf("unknown --agent %q; known agents are %v, or %q",
				name, knownAgents(), AgentAuto)
		}
		wanted[name] = true
	}
	var out []*agentTarget
	for _, name := range knownAgents() {
		if wanted[name] {
			out = append(out, agentTargets[name])
		}
	}
	return out, nil
}

// detectAgents reports which known agents dir carries evidence of, in the sense
// the scope means: an agent's own configuration in a home, or its per-project
// configuration in a tree.
//
// Evidence, not proof.  A directory left behind by trying an agent once reads
// the same as one in daily use, which is why naming an agent is what configures
// it unconditionally and this only ever adds.
func detectAgents(scope agentScope, dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, name := range knownAgents() {
		for _, path := range agentTargets[name].markers(scope) {
			if exists(filepath.Join(dir, path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// detectedAgents is detectAgents over a tree, for the report that names what
// was found and not enrolled.
func detectedAgents(dir string) []string { return detectAgents(scopeTree, dir) }

// agentNames are the known agents, sorted, so a report reads the same twice.
func agentNames() []string {
	out := make([]string, 0, len(agentTargets))
	for name := range agentTargets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}
