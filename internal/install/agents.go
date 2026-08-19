package install

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
)

// An agentTarget is one coding agent's enrolment: the files faramir writes into
// a tree so that agent runs its commands through the broker. Configured for
// the agents that are there, or for the ones named: enrolling trades away every
// Bash prompt in the project on some agents, so `auto` will not configure one
// nobody runs.
type agentTarget struct {
	name string

	// files are written relative to the tree. A list rather than named fields:
	// an agent may split its hook settings from its MCP registration or keep both
	// in one file, and some have no hook to register at all.
	files []agentFile

	// accountFiles go into the agent account's home rather than a tree. They
	// refuse to open key material wherever the agent is working and take nothing
	// away, so no project has to opt in. Rendered, the paths refused being this
	// install's.
	accountFiles []agentFile

	// withoutAccountRules is why this agent has no accountFiles: pi's rules are
	// compiled into the extension an enrolment installs, and Antigravity has none
	// anywhere, which is the difference between covered and not. Required of
	// every target with no accountFiles, and empty for the rest.
	withoutAccountRules string

	// detect names the paths that mean this tree is already configured for this
	// agent. Named rather than derived from files, which are only what faramir
	// writes; generic names stay out, a .mcp.json naming no particular agent.
	detect []string

	// detectHome is the same question about the agent account's home: an agent
	// keeps its per-project configuration beside the project and its own under a
	// home, and the two are not the same paths. faramir's own rule file counts
	// as evidence, which is what makes a second `init` refresh what the first
	// wrote instead of deciding the agent is gone.
	detectHome []string

	// homeInstructions is the file this agent reads as prose wherever it is
	// working, relative to the agent account's home, and is where `init` writes
	// the account-wide credentials section. Its own path per agent and not
	// derivable from detectHome.
	//
	// Written because the deny rules beside it hold wherever the agent works and
	// otherwise arrive at the model as a bare permission error, which is what
	// invites the workaround: another tool, an interpreter, a base64 pipe.
	//
	// Two agents may name the same file, and what is written there then has to
	// hold for both. See runner.agentInstructions.
	homeInstructions string

	// treeInstructions is where this agent reads prose in one tree, for an agent
	// that reads none of the names at the tree's root: Antigravity loads
	// .agents/rules and no documented file beside them. Empty for every other
	// agent, which reads the tree's own file.
	treeInstructions treeRules

	// autoApprovesBash records what enrolling costs on this agent. Claude Code
	// is the one that pays it: a rewritten command matches no permission rule and
	// the hook must approve it, so every Bash prompt in the project is gone.
	// Every other agent has no allow to return, so its prompts are untouched.
	autoApprovesBash bool

	// note is warned about on enrolment, for anything that is not the Bash
	// trade.
	note string

	// noteStands says the note describes what this tree is rather than what this
	// run just did, so it is warned about on every enrolment rather than only on
	// the one that wrote the files.
	noteStands bool
}

// treeRules is one agent's own instructions file inside a tree, and what has to
// head it for the agent to load it at all.
type treeRules struct {
	// path is relative to the tree. Empty where the tree's own AGENTS.md is
	// what this agent reads.
	path string
	// head is written before the markers in a file this creates, and only there:
	// an existing file's first line is its own, and one faramir wrote cannot be
	// told from one the operator did.
	head string
}

type agentFile struct {
	// path is relative to the tree.
	path string
	// asset is the embedded file to write, rendered as a text/template whatever
	// it is named: accountFiles against the install Layout, files against the
	// per-target pluginData.
	asset string
	// mode is 0o640 throughout: an enrolled tree is shared with the client group,
	// so group-readable is what the rest of the tree is, and group-writable is
	// what these must never be, .claude/settings.json naming the PreToolUse hook.
	// It keeps the group from writing through the file and not from replacing it,
	// unlink being a permission on the directory. See sharetree.Options.Keep.
	mode os.FileMode
	// defaultExport renders a plugin as a default-exported { id, server } rather
	// than a named export. The one thing the two plugin hosts disagree about.
	defaultExport bool
	// merge merges faramir's keys into an existing file rather than replacing it,
	// and requires the asset to be JSON. True for every shared config; false
	// only where the path is faramir's own.
	merge bool
}

var agentTargets = map[string]*agentTarget{
	"claude": {
		name: "claude",
		files: []agentFile{
			{path: ".claude/settings.json", asset: "agent/claude/settings.project.json.tmpl", mode: 0o640, merge: true},
			{path: ".mcp.json", asset: "agent/mcp.json.tmpl", mode: 0o640, merge: true},
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
	// opencode and Kilo Code extend through in-process plugins rather than a
	// hook that runs a program, so what is installed is a JavaScript file that
	// calls `faramir guard` and applies what it answers. The deny list and the
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
		// Deny rules only, and no catch-all. The last matching wildcard wins
		// and the merge re-serialises with keys sorted, so an operator's rule
		// sorting after one of these takes effect. Sorting puts a catch-all
		// first, and there is no default this is entitled to replace.
		accountFiles: []agentFile{
			{path: ".config/opencode/opencode.json", asset: "agent/permissions.json.tmpl", mode: 0o640, merge: true},
		},
		detect:           []string{".opencode", "opencode.json", "opencode.jsonc"},
		detectHome:       []string{".config/opencode", ".local/share/opencode"},
		homeInstructions: ".config/opencode/AGENTS.md",
		// No escalation is given or asked for: a plugin that has not thrown has
		// approved nothing, so the agent still prompts as it would have.
		autoApprovesBash: false,
		note:             pluginNote("opencode"),
	},

	// pi extends through a TypeScript module loaded from the project, once the
	// project is trusted. No MCP ships with it, so that module registers the
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
		// from the same list. It refuses a tool call carrying a command through
		// the guard, and one carrying a path against those rules.
		withoutAccountRules: "carries its rules in the extension enrolling a tree " +
			"installs, so there is none of it here",
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
			// preserve the comments a .jsonc is kept for. Both are read.
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
		// which is loaded for every project. Kilo Code has no single named home
		// instructions file to add a section to.
		homeInstructions: ".kilocode/rules/faramir.md",
		autoApprovesBash: false,
		note:             pluginNote("Kilo Code"),
	},

	// Antigravity is the weak one, and enrolling it says so. Its PreToolUse
	// hooks decide -- deny, allow, ask, force_ask -- and cannot change a tool
	// call's arguments, so no command it runs can be routed through the broker
	// and nothing redacts what comes back. Its permission lists are the IDE's
	// own state rather than a file an install may write, so there are no deny
	// rules to put in a home either.
	//
	// What an enrolment leaves is a route and the prose telling it to take one:
	// the MCP tools, and the credentials section in the two files it reads. An
	// agent that skips the prose runs the command itself and the value reaches
	// the model. Configured anyway rather than declined, the route being worth
	// having where it is taken, and the reports and the docs say which half is
	// missing.
	"antigravity": {
		name: "antigravity",
		files: []agentFile{
			{path: ".agents/mcp_config.json", asset: "agent/mcp.json.tmpl", mode: 0o640, merge: true},
		},
		// Nothing account-wide: its permission lists are the IDE's own state and
		// its hooks can only decide, so no file an install writes would refuse a
		// file tool anything.
		withoutAccountRules: "has no file an install can write rules into, its " +
			"permission lists being the IDE's own state, so nothing on this host " +
			"refuses its file tools key material: it is told the policy and nothing " +
			"enforces it",
		// The workspace and legacy customization directories, named by the files in
		// them rather than by the directory: .agents is a name other tools may keep
		// their own things under.
		detect: []string{".agents/rules", ".agents/mcp_config.json", ".agent/rules"},
		// Its own directories, and the customization directory the whole
		// Antigravity family reads.
		detectHome: []string{".antigravity", ".config/Antigravity", ".gemini/config"},
		// Antigravity's global rules, applied in every workspace. Under ~/.gemini,
		// which is the family directory rather than a second agent's.
		homeInstructions: ".gemini/GEMINI.md",
		// It loads .agents/rules and no documented file at the root of a tree, so
		// the section in the tree's AGENTS.md would not reach it.
		treeInstructions: treeRules{
			path: ".agents/rules/faramir.md",
			// A rule's activation is frontmatter and always-on is not the default,
			// so a file without this is one the model may never be shown.
			head: "---\ntrigger: always_on\n---\n",
		},
		// Nothing is approved on its behalf, there being no escalation to give.
		autoApprovesBash: false,
		// Said on every enrolment: what is missing here is missing for as long as
		// the tree is enrolled.
		noteStands: true,
		note: "nothing written here redacts what Antigravity runs. Its hooks decide " +
			"and cannot rewrite a command, so the broker is a route it has to take " +
			"rather than one it is put on: what was installed is the MCP tools and the " +
			"instructions to use them, and a command it runs itself reaches the model " +
			"with the value in it",
	},
}

// writeAgentFiles writes one list of an agent's files under root, and reports
// whether it changed anything and what it wrote. One function for both
// commands: `init` writes the account-wide rules into a home and `init-project`
// the hook and the MCP registration into a tree.
//
// render is the caller's, the two rendering against different things: the
// install layout for an account file, the target's own data for a tree's.
//
// inTree says which root this is. A tree's files are group-owned so the client
// group can read what the hook and the MCP registration are written into, and a
// link out of the tree would carry that group to a file the enrolment was never
// pointed at. A home's decide neither, so an existing file keeps its group and
// a link may land wherever the operator keeps their dotfiles.
func writeAgentFiles(fs fsys, root string, uid, gid int, dirMode os.FileMode,
	inTree bool, render func(agentFile) ([]byte, error),
	files []agentFile) (bool, []string, error) {
	changed := false
	var written []string
	for _, file := range files {
		path := filepath.Join(root, file.path)
		// Only created, never re-owned: the directory is the account's or the
		// project's, and with the operator's own group, `init` running as root so a
		// new ~/.config would otherwise be operator:root.
		//
		// Skipped where the file sits at the root, which has an owner already. In
		// a tree, every level: see ensureDirs. In a home the leaf only, an
		// ancestor there being ~/.config, which 0755 is right for.
		if parent := filepath.Dir(path); parent != filepath.Clean(root) {
			ensure := func() error {
				_, err := fs.ensureDir(parent, dirMode, uid, gid, false)
				return err
			}
			if inTree {
				ensure = func() error {
					return fs.ensureDirsIn(root, parent, dirMode, uid, gid)
				}
			}
			if err := ensure(); err != nil {
				return changed, written, err
			}
		}
		// A link followed and the owner checked: these are the operator's and the
		// project's files, and both commands run as root on a path the account the
		// agent runs as can write. See fsys.editedFile.
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
		// edit, and only the keys faramir writes are touched. Through the merge
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
		// Ownership is set on a file this creates and left alone on one already
		// there, editedFile having established that it is the operator's. The
		// group is asserted in a tree, where the client group has to read these;
		// in a home it decides nothing. The mode is asserted throughout: these
		// carry the hook, and group-writable is what they must never be.
		writeUID, writeGID := uid, gid
		if spot.info != nil {
			// Read off the file: a write renames a new file over the path, so
			// anything not named here comes out owned by root.
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

// refuseUnwritable asks, of every file a run is about to edit, the question the
// write will ask, and answers with what it would refuse.
//
// Asked before anything is written: an enrolment's first step chowns and chmods
// every file in the tree and nothing undoes that, so finding out afterwards
// that a settings file is not the operator's is too late.
//
// Every path, not the first refusal: an operator fixing these wants the list.
// One call per root, and every path a run writes there in it: two of them
// resolving to one file is a refusal, which a caller asking in several calls
// would not find.
func refuseUnwritable(fs fsys, root string, uid int, within string, paths []string) []string {
	var refused []string
	// The file each path resolves to, against the path that named it first. A
	// link is followed, so two of these can be one file: see oneFileTwice.
	claimed := map[string]string{}
	for _, rel := range paths {
		path := filepath.Join(root, rel)
		spot, err := fs.editedFile(path, uid, within)
		target := ""
		if spot != nil {
			target = spot.path
		}
		spot.close()
		if err != nil {
			refused = append(refused, fmt.Sprintf("%s: %v", path, err))
			continue
		}
		// The same path twice is one file written once, which is what two agents
		// reading one file of their own is. Only two different paths landing on
		// one are two writes with one survivor.
		switch first, taken := claimed[target]; {
		case !taken:
			claimed[target] = path
		case first != path:
			refused = append(refused, fmt.Sprintf("%s: %s", path, oneFileTwice(first)))
		}
	}
	return refused
}

// oneFileTwice is what a run says about two of its paths resolving to one file.
// Refused rather than reconciled: each file is written for the agent that reads
// it, so one standing in for two keeps whichever was written last and leaves an
// agent holding another agent's configuration. It names the path that claimed
// the file first, neither half of the pair being wrong on its own.
func oneFileTwice(first string) string {
	return "this and " + first + " are one file, and each is written for the " +
		"agent that reads it, so nothing was written: what one holds would be " +
		"what was written for the other, and only the last write would survive. " +
		"A link between them is what makes this, so point one at a file of its own"
}

// editedPaths are the files one agent's enrolment edits at this scope, relative
// to the root, which is what refuseUnwritable is asked about.
func editedPaths(target *agentTarget, inTree bool, instructions string) []string {
	var out []string
	files := target.accountFiles
	if inTree {
		files = target.files
	}
	for _, file := range files {
		out = append(out, file.path)
	}
	if instructions != "" {
		out = append(out, instructions)
	}
	return out
}

// homeEditedPaths are the files `init` edits in a home for these agents, each
// named once: two agents can read one instructions file.
func homeEditedPaths(targets []*agentTarget) []string {
	var out []string
	seen := map[string]bool{}
	for _, target := range targets {
		for _, path := range editedPaths(target, false, target.homeInstructions) {
			if seen[path] {
				continue
			}
			seen[path] = true
			out = append(out, path)
		}
	}
	return out
}

// pluginNote is what an enrolment says about an agent that matches its bash
// permission rules against the command text. Whether those rules run after the
// rewrite is undocumented, so this states the symptom.
func pluginNote(agent string) string {
	const wrapper = "source " + DefaultLibexecDir + "/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + " '<command>'`. Whether those " +
		"rules see the command or the rewrite is not documented: if commands start " +
		"prompting as the wrapper rather than as themselves, they see the rewrite, and a " +
		"rule naming `" + wrapper + " *` is what decides them from then on"
}

// AgentAuto is the --agent value that means "whichever ones are here", and the
// default on both commands. A name alongside it is configured whether or not
// it is here, so `--agent auto --agent pi` reads as "what is installed, plus
// pi".
const AgentAuto = "auto"

// agentScope is where auto looks for evidence: `init` writes into the agent
// account's home, and `init-project` into one tree.
type agentScope int

const (
	// scopeHome is the agent account's home directory.
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

// KnownAgents lists the agents this can enrol, sorted. Exported so the flag
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
// what dir carries. An unknown name is an error rather than a skip, which
// would leave an operator believing something is covered.
//
// Naming an agent configures it whether or not it is here and auto only adds
// what it finds, so the result is the union of the two. Returned in a fixed
// order, so a report reads the same twice.
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

// detectAgents reports which known agents dir carries evidence of: an agent's
// own configuration in a home, or its per-project configuration in a tree.
// Evidence, not proof -- a directory left behind by trying an agent once reads
// the same as one in daily use -- which is why this only ever adds.
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
