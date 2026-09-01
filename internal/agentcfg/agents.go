package agentcfg

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"

	"github.com/andornaut/faramir/internal/hostfs"
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
	// is the one that pays it: a rewritten command matches no permission rule and
	// the hook must approve it, so every Bash prompt in the project is gone.
	// Every other agent has no allow to return, so its prompts are untouched.
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

// AntigravityFamily is the CLI and the IDE, which ship one hook contract and
// one rule syntax between them. It is the dialect name the guard is registered
// under in a tree, so the registration does not change with which half of the
// family the enrolment named.
const AntigravityFamily = "antigravity"

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
const codexNote = "Codex does not run a hook it has not been told to trust, and says nothing when " +
	"it skips one, so until you start Codex once and trust this hook nothing here is " +
	"routed or refused. Codex must also run without its own sandbox " +
	"(`codex --dangerously-bypass-approvals-and-sandbox`): sandboxed, it is refused the " +
	"broker socket, and every command's output is withheld rather than redacted"

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
		// The only tree file any agent still gets, and for the only thing that
		// costs a permission: the hook that rewrites a command has to approve it,
		// and that approval covers every command the deny list does not name. An
		// operator takes that trade one tree at a time. Everything else Claude Code
		// gets is account-wide, including a deny-only copy of this hook.
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
	// The hook is per tree, so it reaches an agent only in a tree that was
	// enrolled. Antigravity loads a tree's customizations once that tree is a
	// project it has opened, and until then the files are there and inert. Said
	// on enrolment, because nothing else reports it.
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
		Family:       AntigravityFamily,
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

// WriteFiles writes one list of an agent's files under root, and reports
// whether it changed anything and what it wrote. One function for both
// commands: `init` writes the account-wide rules into a home and `init-project`
// Claude Code's routing hook into a tree.
//
// render is the caller's, the two rendering against different things: the
// install layout for an account file, the target's own data for a tree's.
//
// inTree says which root this is. A tree's files are group-owned so the client
// group can read what the hook is written into, and a link out of the tree
// would carry that group to a file the enrolment was never pointed at. A home's decide neither, so an existing file keeps its group and
// a link may land wherever the operator keeps their dotfiles.
// configDir is where the record of what faramir last wrote lives, so a merge
// can take out a rule the config no longer declares. Empty leaves the record
// unread and unwritten, which is a merge that only ever adds.
// warn receives what could not be recorded, which is not a reason to stop:
// the rules reached the file, and what was lost is the note saying faramir
// wrote them. Said rather than swallowed, because the run that meets it next
// removes nothing and nothing else would explain why.
func WriteFiles(fs hostfs.FS, warn func(string, ...any), root, configDir string,
	uid, gid int, dirMode os.FileMode, inTree bool,
	render func(File) ([]byte, error), files []File) (bool, []string, error) {
	changed := false
	var written []string
	for _, file := range files {
		path := filepath.Join(root, file.Path)
		// Only created, never re-owned: the directory is the account's or the
		// project's, and with the operator's own group, `init` running as root so a
		// new ~/.config would otherwise be operator:root.
		//
		// Skipped where the file sits at the root, which has an owner already. In
		// a tree, every level: see ensureDirs. In a home the leaf only, an
		// ancestor there being ~/.config, which 0755 is right for.
		if parent := filepath.Dir(path); parent != filepath.Clean(root) {
			ensure := func() error {
				_, err := fs.EnsureDir(parent, dirMode, uid, gid, false)
				return err
			}
			if inTree {
				// The sticky bit on the directory this file lands in, applied as it is
				// created rather than left to the share's walk: that walk runs before
				// this writes anything, so a directory created here would sit
				// group-writable with no sticky bit until a second enrolment settled
				// it, and in that window the account brokered commands run as can
				// unlink the rules file and put its own there. Only the last
				// component: sharetree.stickyDirs names the directory a kept file sits
				// in and no level above it, and a level this made sticky that the walk
				// does not would be cleared on the next run.
				ensure = func() error {
					return fs.EnsureDirsIn(root, parent, dirMode, dirMode|os.ModeSticky,
						uid, gid)
				}
			}
			if err := ensure(); err != nil {
				return changed, written, err
			}
		}
		// A link followed and the owner checked: these are the operator's and the
		// project's files, and both commands run as root on a path the account the
		// agent runs as can write. See hostfs.FS.EditedFile.
		bound := ""
		if inTree {
			bound = root
		}
		// The rules this run renders into the file, for the record kept after the
		// write. Nil where nothing was merged, which is a file faramir owns
		// outright rather than one it writes into.
		var rendered []string
		spot, err := fs.EditedFile(path, uid, bound)
		if err != nil {
			return changed, written, fmt.Errorf("%s: %w", path, err)
		}
		data, err := render(file)
		if err != nil {
			spot.Close()
			return changed, written, err
		}
		// Merged, not overwritten: the file is the operator's or the project's to
		// edit, and only the keys faramir writes are touched. Through the merge
		// even with nothing to merge into, so the first write is byte-for-byte
		// what the second would produce.
		if file.Merge {
			was, err := spot.Read()
			if err != nil {
				spot.Close()
				return changed, written, err
			}
			// What an earlier run rendered into this file, so a rule the config
			// no longer declares comes out rather than accumulating beside the
			// new ones. See writtenrules.go.
			merged, err := MergeJSON(was, data, ReadWrittenRules(configDir)[path])
			if err != nil {
				spot.Close()
				return changed, written, fmt.Errorf("%s: %w", path, err)
			}
			rendered = jsonStrings(data)
			data = merged
		}
		// Ownership is set on a file this creates and left alone on one already
		// there, editedFile having established that it is the operator's. The
		// group is asserted in a tree, where the client group has to read these;
		// in a home it decides nothing. The mode is asserted throughout: these
		// carry the hook, and group-writable is what they must never be.
		writeUID, writeGID := uid, gid
		if spot.Info() != nil {
			// Read off the file: a write renames a new file over the path, so
			// anything not named here comes out owned by root.
			ownerUID, ownerGID := hostfs.OwnerOf(spot.Info())
			writeUID = ownerUID
			if !inTree {
				writeGID = ownerGID
			}
		}
		made, err := fs.WriteEdited(spot, data, file.Mode, writeUID, writeGID)
		spot.Close()
		if err != nil {
			return changed, written, err
		}
		// After the write and not before it: a record naming rules that never
		// reached the file would have the next run trying to remove what is not
		// there. Not fatal, because the rules did reach the file and what was
		// lost is the note saying faramir wrote them; said, because the run that
		// meets it next removes nothing and nothing else would explain why.
		if rendered != nil {
			if err := recordWrittenRules(configDir, path, rendered); err != nil && warn != nil {
				warn("what faramir wrote into %s was not recorded (%v), so a later "+
					"run will not offer to take those rules out again. Re-run this "+
					"command once nothing else is writing the install", path, err)
			}
		}
		changed = changed || made
		written = append(written, path)
	}
	return changed, written, nil
}

// RefuseUnwritable asks, of every file a run is about to edit, the question the
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
func RefuseUnwritable(fs hostfs.FS, root string, uid int, within string, paths []string) []string {
	var refused []string
	// The file each path resolves to, against the path that named it first. A
	// link is followed, so two of these can be one file: see oneFileTwice.
	claimed := map[string]string{}
	for _, rel := range paths {
		path := filepath.Join(root, rel)
		spot, err := fs.EditedFile(path, uid, within)
		target := ""
		if spot != nil {
			target = spot.Path()
		}
		spot.Close()
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
// Blocked rather than reconciled: each file is written for the agent that reads
// it, so one standing in for two keeps whichever was written last and leaves an
// agent holding another agent's configuration. It names the path that claimed
// the file first, neither half of the pair being wrong on its own.
func oneFileTwice(first string) string {
	return "this and " + first + " are one file, and each is written for the agent that reads it, so nothing was " +
		"written: only the last write would survive. A link between them is what makes " +
		"this, so point one at a file of its own"
}

// EditedPaths are the files one agent's enrolment edits at this scope, relative
// to the root, which is what RefuseUnwritable is asked about.
func EditedPaths(target *Target, inTree bool, instructions string) []string {
	var out []string
	files := target.AccountFiles
	if inTree {
		files = target.Files
	}
	for _, file := range files {
		out = append(out, file.Path)
	}
	if instructions != "" {
		out = append(out, instructions)
	}
	return out
}

// HomeEditedPaths are the files `init` edits in a home for these agents, each
// named once: two agents can read one instructions file.
func HomeEditedPaths(targets []*Target) []string {
	var out []string
	seen := map[string]bool{}
	for _, target := range targets {
		for _, path := range EditedPaths(target, false, target.HomeInstructions) {
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
	const wrapper = "source " + hostlayout.DefaultLibexecDir + "/wrap.sh"
	return agent + " matches its bash permission rules against the command text, and the " +
		"guard rewrites every command into `" + wrapper + "'<command>'`. Whether those rules see the command or the rewrite is not " +
		"documented: if commands prompt as the wrapper, they see the rewrite, and a rule " +
		"naming `" + wrapper + " *` is what decides them from then on"
}

// Auto is the --agent value that means "whichever ones are here", and the
// default on both commands. A name alongside it is configured whether or not
// it is here, so `--agent auto --agent pi` reads as "what is installed, plus
// pi".
const Auto = "auto"

// Scope is where auto looks for evidence: `init` writes into the agent
// account's home, and `init-project` into one tree.
type Scope int

const (
	// ScopeHome is the agent account's home directory.
	ScopeHome Scope = iota
	// ScopeTree is one working tree.
	ScopeTree
)

func (t *Target) markers(scope Scope) []string {
	if scope == ScopeHome {
		return t.DetectHome
	}
	return t.Detect
}

// Known lists the agents this can enrol, sorted for a stable error, and so for
// the flag that takes one to name them rather than carry a copy.
func Known() []string {
	out := make([]string, 0, len(Targets))
	for name := range Targets {
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// Resolve turns --agent values into targets, resolving "auto" against
// what dir carries. An unknown name is an error rather than a skip, which
// would leave an operator believing something is covered.
//
// Naming an agent configures it whether or not it is here and auto only adds
// what it finds, so the result is the union of the two. Returned in a fixed
// order, so a report reads the same twice.
// home is the agent account's home, consulted for an agent that keeps nothing
// of its own beside a project; empty where the caller has none to give, which
// leaves such an agent undetected rather than guessed at.
func Resolve(names []string, scope Scope, dir, home string) ([]*Target, error) {
	if len(names) == 0 {
		names = []string{Auto}
	}
	wanted := map[string]bool{}
	for _, name := range names {
		if name == Auto {
			for _, found := range detectForEnrolment(scope, dir, home) {
				wanted[found] = true
			}
			continue
		}
		if _, ok := Targets[name]; !ok {
			return nil, fmt.Errorf("unknown --agent %q; known agents are %v, or %q",
				name, Known(), Auto)
		}
		wanted[name] = true
	}
	var out []*Target
	for _, name := range Known() {
		if wanted[name] {
			out = append(out, Targets[name])
		}
	}
	return out, nil
}

// detect reports which known agents dir carries evidence of: an agent's
// own configuration in a home, or its per-project configuration in a tree.
// Evidence, not proof -- a directory left behind by trying an agent once reads
// the same as one in daily use -- which is why this only ever adds.
func detect(scope Scope, dir string) []string {
	if dir == "" {
		return nil
	}
	var out []string
	for _, name := range Known() {
		for _, path := range Targets[name].markers(scope) {
			if hostfs.Exists(filepath.Join(dir, path)) {
				out = append(out, name)
				break
			}
		}
	}
	return out
}

// detectForEnrolment is the question auto puts: which agents should this run
// configure here. It is Detect plus the home fallback, which is a
// different question from what a tree carries. [enrolled] asks that other one
// and keeps Detect, an agent's enrolment record being what a tree still
// shows rather than what the host has installed.
func detectForEnrolment(scope Scope, dir, home string) []string {
	out := detect(scope, dir)
	if scope != ScopeTree || home == "" {
		return out
	}
	for _, name := range Known() {
		target := Targets[name]
		if !target.DetectsFromHome || slices.Contains(out, name) {
			continue
		}
		for _, path := range target.DetectHome {
			if hostfs.Exists(filepath.Join(home, path)) {
				out = append(out, name)
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

// Detected is what auto would find in a tree, for the report that names
// what was found and not enrolled.
func Detected(dir, home string) []string {
	return detectForEnrolment(ScopeTree, dir, home)
}
