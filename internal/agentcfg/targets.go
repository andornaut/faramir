package agentcfg

// The catalogue itself: which agents there are, which files each keeps in a
// home and in a tree, and how to tell that one is in use. Data rather than
// behaviour, which is in write.go and resolve.go.

import (
	"os"

	"github.com/andornaut/faramir/internal/hostlayout"
)

// A Target is one coding agent's enrolment: the files faramir writes into
// a tree so that agent runs its commands through the broker. Configured for
// the agents that are there, or for the ones named: enrolling trades away every
// Bash prompt in the project on some agents, so `auto` will not configure one
// nobody runs.
type Target struct {
	Name string

	// Family is the agents that share one tree enrolment, for the two that ship
	// a single hook contract between them and are told apart only by what they
	// keep in a home. Empty for an agent that is its own family, which is every
	// other one.
	//
	// It decides two things. A tree's files are rendered against it rather than
	// against the name, so enrolling either member writes the same bytes and a
	// second enrolment naming the other is a no-op rather than a rewrite. And a
	// sibling detected in a tree an enrolment already covered is not reported as
	// an agent nothing redacts, which it is not.
	Family string

	// Files are written relative to the tree. A list rather than named fields:
	// an agent may split its hook settings from its MCP registration or keep both
	// in one file, and some have no hook to register at all.
	Files []File

	// AccountFiles go into the agent account's home rather than a tree. They
	// refuse to open key material wherever the agent is working and take nothing
	// away, so no project has to opt in. Rendered, the paths refused being this
	// install's.
	AccountFiles []File

	// Detect names the paths that mean this tree is already configured for this
	// agent. Named rather than derived from Files, which are only what faramir
	// writes; generic names stay out, a .mcp.json naming no particular agent.
	Detect []string

	// DetectHome is the same question about the agent account's home: an agent
	// keeps its per-project configuration beside the project and its own under a
	// home, and the two are not the same paths. faramir's own rule file counts
	// as evidence, which is what makes a second `init` refresh what the first
	// wrote instead of deciding the agent is gone.
	DetectHome []string

	// DetectsFromHome is for an agent that keeps nothing of its own beside a
	// project, so the only thing a tree can carry for it is the file an enrolment
	// writes. Asked of the tree alone, auto could only ever find such an agent
	// already enrolled, and would never enrol it a first time. So the tree
	// question is put to the home instead, where the evidence of using the agent
	// actually is. Naming it explicitly still enrols it, as for any agent.
	DetectsFromHome bool

	// HomeInstructions is the file this agent reads as prose wherever it is
	// working, relative to the agent account's home, and is where `init` writes
	// the account-wide credentials section. Its own path per agent and not
	// derivable from DetectHome.
	//
	// Written because the deny rules beside it hold wherever the agent works and
	// otherwise arrive at the model as a bare permission error, which is what
	// invites the workaround: another tool, an interpreter, a base64 pipe.
	//
	// Two agents may name the same file, and what is written there then has to
	// hold for both. See install's agentInstructions step.
	HomeInstructions string

	// TreeInstructions is a file of this agent's own inside a tree, for an agent
	// that may read none of the names at the tree's root: Antigravity loads
	// .agents/rules, and Claude Code reads CLAUDE.md and not AGENTS.md. Empty for
	// every other agent, which reads whichever name the tree's own file has.
	//
	// It carries the same section as the tree's own file, so two of these
	// resolving to one file is one write rather than a refusal: see
	// OneSectionPerFile.
	TreeInstructions treeRules

	// AutoApprovesBash records what enrolling costs on this agent. Claude Code
	// is the one that pays it: it refuses the sourced command the rewrite
	// produces whatever permission rules exist, so the hook has to approve what
	// it rewrote, and every Bash prompt in the project goes with it. Every other
	// agent has no allow to return, so its prompts are untouched.
	AutoApprovesBash bool

	// Note is warned about on enrolment, for anything that is not the Bash
	// trade.
	Note string

	// AccountNote is warned about by `init`, for a condition that holds on the
	// account-wide half as well as in a tree. Its own field rather than a scope
	// on Note: every other note is about what an enrolment traded away, and one
	// of those repeated on every `init` would be noise nobody reads.
	AccountNote string

	// NoteStands says the Note describes what this tree is rather than what this
	// run just did, so it is warned about on every enrolment rather than only on
	// the one that wrote the files.
	NoteStands bool
}

// treeRules is one agent's own instructions file inside a tree, and what has to
// head it for the agent to load it at all.
type treeRules struct {
	// Path is relative to the tree. Empty where the tree's own AGENTS.md is
	// what this agent reads.
	Path string
	// Head is written before the markers in a file this creates, and only there:
	// an existing file's first line is its own, and one faramir wrote cannot be
	// told from one the operator did.
	Head string
}

type File struct {
	// Path is relative to the tree.
	Path string
	// Asset is the embedded file to write, rendered as a text/template whatever
	// it is named: an AccountFiles entry against the install layout, a Files entry
	// against the per-target PluginData.
	Asset string
	// Mode is 0o640 throughout: an enrolled tree is shared with the client group,
	// so group-readable is what the rest of the tree is, and group-writable is
	// what these must never be, .claude/settings.local.json naming the PreToolUse
	// hook.
	// It keeps the group from writing through the file and not from replacing it,
	// unlink being a permission on the directory. See sharetree.Options.Keep.
	Mode os.FileMode
	// DefaultExport renders a plugin as a default-exported { id, server } rather
	// than a named export. The one thing the two plugin hosts disagree about.
	DefaultExport bool
	// Merge merges faramir's keys into an existing file rather than replacing it,
	// and requires the asset to be JSON. True for every shared config; false
	// only where the path is faramir's own.
	Merge bool
	// NoRules says this account file carries no path rules, so the checks that
	// ask whether every protected path is refused skip it. Antigravity's
	// account-wide hook is the case: it registers a program and names no path,
	// and reading it as a rule file reports every path as unrefused.
	//
	// Negative on purpose. The default is that an account file carries rules, so
	// one added without a thought about this is checked rather than skipped, and
	// the failure of forgetting is a report that is too strict rather than one
	// that quietly passes.
	NoRules bool

	// Local says the agent reads this file as the operator's rather than the
	// repository's, so it belongs in git's ignores: everything faramir writes
	// into one names a path this machine decided. An enrolment says so when it
	// is not ignored; see project.warnUncommittableFiles.
	Local bool
}

// antigravityFamily is the CLI and the IDE, which ship one hook contract and
// one rule syntax between them. It is the dialect name the guard is registered
// under in the account-wide hook `faramir init` writes, so the registration does
// not change with which half of the family `--agent` named.
const antigravityFamily = "antigravity"

// agySettingsFile is the CLI's own deny-rules file, named here as well as in
// its target because the coverage check has to know which file cannot express
// four of the five name-pattern kinds.
const agySettingsFile = ".gemini/antigravity-cli/settings.json"

// The files an Antigravity enrolment writes into a tree. Named once: a path
// spelled two ways is a second file the agent does not read.
const (
	antigravityHooks = ".agents/hooks.json"
	// pi's extension, which goes into a home rather than a tree.
	piExtensionAsset = "agent/pi/extension.ts.tmpl"
	// The plugin the two plugin hosts load, written into a tree by an enrolment
	// and into a home by `init`. One asset: the two copies differ only in what
	// the guard is asked, which is rendered.
	pluginAsset = "agent/plugin.js.tmpl"
	// Antigravity's own MCP registration. faramir writes none: the broker is
	// reached through the binary, which is installed for the account and needs no
	// registration anywhere. It stays here as evidence that a tree is one this
	// agent works in, which is what detection asks.
	antigravityMCP = ".agents/mcp_config.json"
	// The customization directory the whole family reads for every workspace,
	// enrolled or not.
	antigravityAccountHooks = ".gemini/config/hooks.json"
	// CodexHooksFile is Codex's hook file inside a tree. The same name it reads
	// under a home, which is why the two are named apart: one path, two roots,
	// and each renders the half of the enrolment that belongs at its own scope.
	CodexHooksFile = ".codex/hooks.json"
)

// codexNote is the two conditions faramir cannot meet on this agent's behalf,
// and it holds at both scopes: the account-wide hook and a tree's are inert
// under either of them.
//
// Said on every run rather than only on the one that wrote the files. Both fail
// quietly, so neither is safe to leave to be discovered. Trust is reported
// afterwards as well, `doctor` failing on a hook Codex will not run; how Codex
// was started is not something a later run can know, and is said here alone.
const codexNote = "Codex skips a hook it has not been told to trust, silently, so nothing here is " +
	"routed or refused until you start Codex once and trust this hook. Codex must also " +
	"run without its own sandbox (`codex --dangerously-bypass-approvals-and-sandbox`): " +
	"sandboxed, it cannot reach the broker socket, and every command's output is " +
	"withheld instead of redacted"

// FamilyName is the tree enrolment this target belongs to, which is the target
// itself where it shares one with nobody.
func (t *Target) FamilyName() string {
	if t.Family == "" {
		return t.Name
	}
	return t.Family
}

var Targets = map[string]*Target{
	"claude": {
		Name: "claude",
		// A tree-level settings file, which only Claude Code and Codex get, for
		// the one thing that suppresses a permission prompt: the hook that
		// rewrites a command has to approve it, and that approval covers every
		// command the deny list does not name. An operator accepts that per
		// tree, by enrolling it. The
		// tree instructions file below is the other thing a tree gets. Everything
		// else Claude Code gets is account-wide, including a deny-only copy of
		// this hook.
		Files: []File{
			{Path: ".claude/settings.local.json", Asset: "agent/claude/settings.local.json.tmpl", Mode: 0o640, Merge: true, Local: true},
		},
		// Read and Edit rules only: Claude Code matches file permission checks
		// against Edit(path), which covers every file-editing tool, and a
		// Write(path) rule matches nothing.
		AccountFiles: []File{
			{Path: ".claude/settings.json", Asset: "agent/claude/settings.json", Mode: 0o640, Merge: true},
		},
		Detect:           []string{".claude"},
		DetectHome:       []string{".claude", ".claude.json"},
		HomeInstructions: ".claude/CLAUDE.md",
		// Claude Code reads CLAUDE.md and not AGENTS.md, so a tree whose own file
		// is an AGENTS.md leaves this agent nothing. Named here rather than left to
		// the tree's own file, which is whichever name the tree already has.
		//
		// An operator who keeps one file for every agent links CLAUDE.md at
		// AGENTS.md, and then this and the tree's own file are one file: written
		// once, the two carrying the same section. See OneSectionPerFile.
		TreeInstructions: treeRules{Path: "CLAUDE.md"},
		AutoApprovesBash: true,
	},
	// Codex reads the same hook contract Claude Code does, and its enrolment is
	// shaped the same way for the same reason: a rewrite has to be approved to
	// run, and the allow that approves it covers every command the deny list does
	// not name. So the account gets a deny-only hook and a tree gets the routing
	// one.
	//
	// Where it differs is what the account-wide half can be. Claude Code takes
	// deny rules in its settings and enforces them itself; Codex's own `.rules`
	// files are an exec policy, which decides commands and names no path, so
	// there is no rule file to write and the hook is the whole of what refuses a
	// file tool. That is why this hook matches every tool rather than Bash: see
	// the assets.
	"codex": {
		Name: "codex",
		Files: []File{
			{Path: CodexHooksFile, Asset: "agent/codex/hooks.tree.json.tmpl", Mode: 0o640, Merge: true, Local: true, NoRules: true},
		},
		AccountFiles: []File{
			{Path: CodexHooksFile, Asset: "agent/codex/hooks.json.tmpl", Mode: 0o640, Merge: true, NoRules: true},
		},
		Detect:     []string{CodexHooksFile},
		DetectHome: []string{".codex"},
		// Codex keeps nothing of its own beside a project, so its only tree marker
		// is the hook file an enrolment writes. Detected from the home instead.
		DetectsFromHome: true,
		// Codex's global instructions, loaded wherever it is working.
		HomeInstructions: ".codex/AGENTS.md",
		// Codex reads AGENTS.md and not CLAUDE.md, the mirror image of Claude
		// Code, so a tree whose own file is a CLAUDE.md would leave this agent
		// nothing. Named here rather than left to the tree's own file, which is
		// whichever name the tree already has; where that name is AGENTS.md the
		// two are one file and the section is written once. See OneSectionPerFile.
		TreeInstructions: treeRules{Path: "AGENTS.md"},
		// Same trade as Claude Code, and only in an enrolled tree: the hook has to
		// approve the command it rewrote, and that approval covers every command
		// the deny list does not name.
		AutoApprovesBash: true,
		NoteStands:       true,
		Note:             codexNote,
		AccountNote:      codexNote,
	},

	// opencode and Kilo Code extend through in-process plugins rather than a
	// hook that runs a program, so what is installed is a JavaScript file that
	// calls `faramir guard` and applies what it answers. The deny list and the
	// rewrite stay in the binary.
	//
	// A plugin directory needs no registration: the host loads every file in it.
	"opencode": {
		Name: "opencode",
		// Deny rules only, and no catch-all. The last matching wildcard wins
		// and the merge re-serialises with keys sorted, so an operator's rule
		// sorting after one of these takes effect. Sorting puts a catch-all
		// first, and there is no default this is entitled to replace.
		AccountFiles: []File{
			{Path: ".config/opencode/opencode.json", Asset: "agent/permissions.json.tmpl", Mode: 0o640, Merge: true},
			// And the plugin, which this host loads for every project. Its rule
			// file above is not a refusal -- a "deny" is put to the operator as a
			// prompt, and an autonomous run approves it -- so without this a tree
			// nobody enrolled has nothing refusing its file tools.
			{Path: ".config/opencode/plugin/faramir.js", Asset: pluginAsset, Mode: 0o640, NoRules: true},
		},
		Detect:           []string{".opencode", "opencode.json", "opencode.jsonc"},
		DetectHome:       []string{".config/opencode", ".local/share/opencode"},
		HomeInstructions: ".config/opencode/AGENTS.md",
		// No escalation is given or asked for: a plugin that has not thrown has
		// approved nothing, so the agent still prompts as it would have.
		AutoApprovesBash: false,
		Note:             pluginNote("opencode"),
	},

	// pi extends through a TypeScript module, which it loads from a home for
	// every project. The module registers no tools and decides nothing: it asks
	// `faramir guard` and applies the answer, the same as the two plugin hosts.
	"pi": {
		Name: "pi",
		// The extension goes in a home, which pi discovers for every project and
		// loads without the project being trusted. A project-local one needs trust,
		// so a tree pi had not been trusted in was unguarded; there is no such tree
		// now. It cannot be in both places: with the same extension global and
		// project-local, pi hangs at startup.
		AccountFiles: []File{
			{Path: ".pi/agent/extensions/faramir.ts", Asset: piExtensionAsset, Mode: 0o640, NoRules: true},
		},
		Detect:     []string{".pi"},
		DetectHome: []string{".pi"},
		// pi reads this one from under its own directory rather than beside a
		// config, and loads it for every project.
		HomeInstructions: ".pi/agent/AGENTS.md",
		// The extension returns a refusal rather than approving anything, so the
		// agent prompts as it would have.
		AutoApprovesBash: false,
		Note:             pluginNote("pi"),
	},

	"kilocode": {
		Name: "kilocode",
		// Deny rules only, and no catch-all, for the reason given on opencode's.
		AccountFiles: []File{
			{Path: ".config/kilo/kilo.json", Asset: "agent/permissions.json.tmpl", Mode: 0o640, Merge: true},
			// And the plugin, beside the rule file, for the reason opencode's is
			// there: the rules are a prompt rather than a refusal, so without this a
			// tree nobody enrolled has nothing refusing its file tools. This host
			// reads a plugin from here and from ~/.kilocode/plugin; the one beside
			// its own rule file is the one an operator finds when they look.
			{Path: ".config/kilo/plugin/faramir.js", Asset: pluginAsset, Mode: 0o640, DefaultExport: true, NoRules: true},
		},
		// .kilocode is the legacy directory, still read.
		Detect:     []string{".kilo", ".kilocode", "kilo.json", "kilo.jsonc"},
		DetectHome: []string{".config/kilo", ".config/kilocode", ".kilocode"},
		// A file of faramir's own in the global rules directory, every .md in
		// which is loaded for every project. Kilo Code has no single named home
		// instructions file to add a section to.
		HomeInstructions: ".kilocode/rules/faramir.md",
		AutoApprovesBash: false,
		Note:             pluginNote("Kilo Code"),
	},

	// The Antigravity family is two agents, not one. They ship a single hook
	// contract and a single rule syntax, and they differ in the one place this
	// package is organised around: whether there is a file an install can write
	// account-wide deny rules into. So they are two targets rather than one with
	// a knob, and each says what it actually gets.
	//
	// Both take the same PreToolUse hook. Antigravity's hooks return a decision
	// and may also return "overwrite", a shallow merge into the tool call's own
	// arguments whose merged form is what runs, so a command it runs is routed
	// through the broker and comes back redacted the way every other agent's
	// does. The rewrite lands on run_command; nothing else carries a command.
	//
	// The hook is account-wide, an account file `faramir init` writes, so it
	// holds in every workspace whether or not the tree was enrolled. What an
	// enrolment writes into a tree is the rules file, which Antigravity loads
	// once that tree is a project it has opened, and until then the file is there
	// and inert. Said on enrolment, because nothing else reports it.
	//
	// The CLI half. Its own deny-rules settings file on top of the family base,
	// held against an operator's own allow by the documented deny-over-allow
	// precedence.
	"agy": antigravityMember(
		"agy",
		// Its own directory, and not the family's shared one. faramir writes
		// ~/.gemini/config/hooks.json for either half, so that directory marks
		// neither: installing for the IDE would otherwise report the CLI as present
		// and its settings file as missing, for a CLI nobody installed. An agent's
		// own file marking itself is deliberate and makes a second `init` a
		// refresh; one agent's file marking another is not.
		[]string{".gemini/antigravity-cli"},
		[]File{
			{Path: agySettingsFile, Asset: "agent/agy/settings.json", Mode: 0o640, Merge: true},
		},
	),

	// The IDE half. Same hook, same prose, and no account-wide rules of its own:
	// its permission scopes are its own state, and no file an install may write
	// was found for them. So commands it runs are routed and redacted, and its
	// file tools are refused only by the shared hook.
	"antigravity": antigravityMember(
		"antigravity",
		// Its own directories at both the names it has used: 2.5 reports a data
		// directory of .antigravity-ide, and the earlier one is .antigravity. Not
		// the family's shared one, for the reason the CLI's own is not.
		[]string{".antigravity-ide", ".config/Antigravity IDE", ".antigravity", ".config/Antigravity"},
		nil,
	),
}

// antigravityMember builds one half of the Antigravity family from the fields
// the two share: the hook both read for every workspace, the tree rules file,
// the family's ~/.gemini/GEMINI.md prose, and the note about when a tree's
// customizations load. name and detectHome are the half's own, and ownRules is
// the CLI's deny-rules settings file, which the IDE has none of.
//
// The two are one dialect in the guard (antigravityHost) and one hook on disk;
// this is the same fact for the config table, so the halves state only what
// actually differs between them.
func antigravityMember(name string, detectHome []string, ownRules []File) *Target {
	// The hook both halves read for every workspace, shared: written once, it
	// holds for whichever half is running.
	sharedHook := File{Path: antigravityAccountHooks, Asset: "agent/antigravity/hooks.json.tmpl",
		Mode: 0o640, Merge: true, NoRules: true}
	return &Target{
		Name:         name,
		Family:       antigravityFamily,
		AccountFiles: append(append([]File{}, ownRules...), sharedHook),
		Detect:       []string{".agents/rules", antigravityHooks, antigravityMCP, ".agent/rules"},
		DetectHome:   detectHome,
		// The family's global rules, applied in every workspace, under ~/.gemini
		// rather than a second agent's directory. Both halves read the same file.
		HomeInstructions: ".gemini/GEMINI.md",
		// A tree's own AGENTS.md is read too, walking up from the file being
		// worked on, so the section there is what every other agent gets. The
		// rules file is written as well: it loads whatever the tree's root file is
		// called, and a tree whose own file is a CLAUDE.md would otherwise leave
		// this agent nothing.
		TreeInstructions: treeRules{
			Path: ".agents/rules/faramir.md",
			// A rule's activation is frontmatter and always-on is not the default,
			// so a file without this is one the model may never be shown.
			Head: "---\ntrigger: always_on\n---\n",
		},
		// The permission check runs before the hook, so the guard's allow is not
		// an approval anything was waiting for: a command with no rule to permit
		// it is refused before this is asked. Nothing is traded away.
		AutoApprovesBash: false,
		NoteStands:       true,
		Note: "Antigravity loads what an enrolment writes into a tree once that tree is a " +
			"project it has opened, so until then the rules file is there and inert. What " +
			"holds meanwhile is the account-wide hook `faramir init` writes",
	}
}

// pluginNote is what an enrolment says about an agent that matches its bash
// permission rules against the command text. Whether those rules run after the
// rewrite is undocumented, so this states the symptom.
func pluginNote(agent string) string {
	const wrapper = "source " + hostlayout.DefaultLibexecDir + "/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + "'<command>'`. Whether those rules see the command or the rewrite is not " +
		"documented: if commands prompt as the wrapper, they see the rewrite, and a rule " +
		"naming `" + wrapper + " *` is what decides them from then on"
}
