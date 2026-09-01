package agentcfg

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

// RuleLayout is what an agent's rule file is rendered against: this install's
// own directories, and the paths its config names as linked or refused. One
// function for both sides, so what `enrol` writes into a tree is what
// `doctor` re-renders to compare it with, and a re-render is not read as drift.
func RuleLayout(configDir string) hostlayout.Layout {
	if configDir == "" {
		configDir = hostlayout.DefaultConfigDir
	}
	layout := hostlayout.Layout{
		ConfigDir: configDir,
		Links:     configuredLinks(configDir),
		Blocked:   ConfiguredBlocked(configDir),
	}
	// The service accounts, read off the installed units the way `doctor` reads
	// them, so a host that renamed one has its state directories rendered at the
	// names it uses. A unit that cannot be read leaves the account empty and
	// Dirs falls back to the standard name, which is what an install that
	// named nothing used.
	layout.BrokerUser, _ = hostunit.User(hostunit.BrokerUnit)
	layout.KeeperUser, _ = hostunit.User(hostunit.KeeperUnit)
	layout.ExecUser, _ = hostunit.User(hostunit.ExecUnit)
	// And the agent's own account, for the same reason: a path under its home is
	// rendered in the spellings a shell expands to it, so a re-render that does
	// not know the home writes fewer rules than the host carries and reports the
	// difference as drift. Read from the config the install rendered from rather
	// than from the caller, so the comparison is against what that file says.
	layout.AgentUser = configuredAgentUser(configDir)

	// The rest of what the shipped pattern file names, so a re-render of it can
	// be compared with the installed one. Taken from the config where the config
	// has it and from the compiled defaults where nothing does: the log
	// directory is where the broker is told to append, the SSH key is what the
	// broker lends, and the binary and libexec directories are fixed at build
	// time and have no key of their own.
	layout.BinDir, layout.LibexecDir = hostlayout.DefaultBinDir, hostlayout.DefaultLibexecDir
	layout.LogDir = hostlayout.DefaultLogDir
	if cfg, err := config.Load(filepath.Join(configDir, "config.toml")); err == nil {
		if cfg.Audit.LogPath != "" {
			layout.LogDir = filepath.Dir(cfg.Audit.LogPath)
		}
		layout.SSHKey = cfg.Ssh.Key
	}
	return layout
}

// configuredLinks is every link the install names, or nothing when the config
// cannot be read: a config that does not load is reported by the check that
// loads it.
func configuredLinks(configDir string) []config.Link {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return nil
	}
	return cfg.Secret.Links
}

// configuredBlocked is every blocked path the install names, on the same
// terms as configuredLinks.
// configuredAgentUser is [server] agent_user as the installed config records
// it, and "" where the config cannot be read: Dirs and the rule
// rendering both skip an empty one, so a home missing from both sides of the
// comparison is not drift.
func configuredAgentUser(configDir string) string {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return ""
	}
	return cfg.Server.AgentUser
}

func ConfiguredBlocked(configDir string) []config.BlockedPath {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return nil
	}
	return cfg.Secret.Blocked
}

// Named reports whether any rule in a file names this path. Containment rather
// than equality, each agent spelling the same path its own way: Claude Code
// writes "Read(/path)" while the plugin hosts key on the path itself.
//
// The match ends at a path character, so a longer path does not vouch for a
// shorter one: with ~/.npmrc and ~/.npmrc-work both linked, a rule naming only
// the second must not report the first as refused.
func Named(entries map[string]bool, path string) bool {
	for entry := range entries {
		for start := 0; ; {
			i := strings.Index(entry[start:], path)
			if i < 0 {
				break
			}
			i += start
			start = i + 1
			// Anchored on the left as well as the right: a path character before
			// the match means a rule about a longer path, so "**/my.env" must not
			// vouch for ".env" any more than ".npmrc-work" vouches for ".npmrc".
			if i > 0 && isPathRune(rune(entry[i-1])) && !anyDirectory(entry[:i]) {
				continue
			}
			rest := entry[i+len(path):]
			// The subtree spelling of this same path. A directory is rendered as
			// "<dir>/**" for Claude Code and "<dir>/*" for the plugin hosts, and
			// without this both read as a longer path and the rule that is there
			// reports as missing. A wildcard is what separates them from a sibling:
			// "/secrets/**" after "/etc/faramir" is a different directory and stays
			// unmatched, and "-notes" after it is stopped by isPathRune already.
			if strings.HasPrefix(rest, "/*") {
				return true
			}
			if rest == "" || !isPathRune(rune(rest[0])) {
				return true
			}
		}
	}
	return false
}

// anyDirectory reports whether what precedes a match is an "in any directory"
// prefix: "**/" for Claude Code and "*/" for the plugin hosts. That separator is
// the left edge of the subject, so the match is the whole of what the rule
// names.
//
// Only that spelling. A separator reached by an actual directory -- the "/"
// before ".env" in a rule naming /home/operator/proj/.env -- is a rule about one
// file, and must not vouch for one that refuses ".env" everywhere. Nothing
// faramir renders takes the wildcard form now that every subject is a path, so
// this holds the line against a rule some other hand wrote into a merged file.
func anyDirectory(before string) bool {
	return strings.HasSuffix(before, "*/")
}

// isPathRune reports whether a byte could continue a path, which is what
// decides whether a match was the whole path or a prefix of a longer one. The
// separators each agent wraps a path in -- ")", quotes, whitespace, a glob --
// are not path characters.
func isPathRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("-_.~+@,:/", r)
}

// StaleRules is the entries in path that name something faramir manages and are
// not in what it writes now.
func StaleRules(path string, current []byte, configDir string) ([]string, error) {
	onDisk, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	have, err := RuleEntries(onDisk)
	if err != nil {
		return nil, err
	}
	want, err := RuleEntries(current)
	if err != nil {
		return nil, err
	}
	var out []string
	for entry := range have {
		if want[entry] || !LooksManaged(entry, configDir) {
			continue
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out, nil
}

// RuleEntries is every rule an agent's config states, in either shape these
// files use: a list of strings, as Claude Code writes its deny rules, and an
// object keyed by pattern, as the plugin hosts write theirs. Shape rather than
// a named path per agent, so an agent that moves its rules to another key is
// still read; a key whose value is not a decision is not a rule.
func RuleEntries(data []byte) (map[string]bool, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	var walk func(any)
	walk = func(node any) {
		switch value := node.(type) {
		case []any:
			for _, element := range value {
				if text, isString := element.(string); isString {
					out[text] = true
					continue
				}
				walk(element)
			}
		case map[string]any:
			for key, child := range value {
				if decision, isString := child.(string); isString && isDecision(decision) {
					out[key] = true
					continue
				}
				walk(child)
			}
		}
	}
	walk(root)
	return out, nil
}

// DenyEntries is the rules that refuse: strings inside an array under a "deny"
// key, and keys whose own value is "deny". ruleEntries above stays the wide
// set for staleRules, which asks about presence rather than direction;
// coverage asked with the wide set read an operator's own allow entry as a
// refusal of the path it grants.
func DenyEntries(data []byte) (map[string]bool, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	var walk func(node any, underDeny bool)
	walk = func(node any, underDeny bool) {
		switch value := node.(type) {
		case []any:
			for _, element := range value {
				if text, isString := element.(string); isString {
					if underDeny {
						out[text] = true
					}
					continue
				}
				walk(element, underDeny)
			}
		case map[string]any:
			for key, child := range value {
				if decision, isString := child.(string); isString {
					if decision == decisionDeny {
						out[key] = true
					}
					continue
				}
				walk(child, underDeny || key == decisionDeny)
			}
		}
	}
	walk(root, false)
	return out, nil
}

// decisions are the verdicts these files spell, and what tells a rule from
// ordinary configuration. "ask" and "allow" are here although faramir writes
// neither, what is read being somebody else's file as well as faramir's.
var decisions = []string{decisionDeny, "allow", "ask"}

// decisionDeny is the one verdict coverage counts; the other two are read only
// to tell a rule from ordinary configuration.
const decisionDeny = "deny"

// isDecision reports whether a value is a permission verdict rather than
// ordinary configuration, which is what makes its key a rule.
func isDecision(value string) bool {
	return slices.Contains(decisions, value)
}

// LooksManaged reports whether an entry names something on faramir's list.
// Nothing here is a record of what earlier versions wrote, a stored list going
// stale the first time somebody edits the file, so this infers from the name: a
// rule naming a layout faramir has stopped using names it by that name.
//
// Generous in one direction and never the other: an operator's own rule
// refusing a path faramir also refuses is reported alongside the leftovers, the
// two being indistinguishable, and the finding says so. A rule about anything
// else is not reported at all.
//
// configDir is the install being examined rather than the default, so a stale
// rule naming a non-default directory still in use is found.
func LooksManaged(entry, configDir string) bool {
	// Its own name: anything under a path with "faramir" in it is faramir's to ask
	// about, whatever layout put it there.
	if strings.Contains(entry, "faramir") {
		return true
	}
	for _, dir := range Dirs(hostlayout.Layout{ConfigDir: configDir}) {
		if strings.Contains(entry, dir) {
			return true
		}
	}
	return false
}

// InstructionFiles are the names an agent reads, most specific first; the
// first is created when there is none.
var InstructionFiles = []string{"AGENTS.md", "CLAUDE.md"}

// HomeFor is the account's home directory.
func HomeFor(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	entry, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return entry.HomeDir, nil
}

// PluginData is what an agent plugin's template is rendered against: the binary
// it execs, which agent it speaks to, and the path it is written to. Not the
// install Layout, none of the last two being install-wide.
type PluginData struct {
	BinDir string
	Agent  string
	// Family is the tree enrolment this file belongs to, and what a registration
	// shared by two agents names itself. See Target.Family.
	Family        string
	Path          string
	DefaultExport bool
	// Layout is what the rule renderers take: this install's own directories and
	// the paths its config names as linked or refused. Built from the enrolment's
	// --config-dir, so a store moved into a home is the one refused rather than
	// the default, and built by RuleLayout so what an enrolment writes is what
	// `doctor` re-renders to compare it with.
	Layout hostlayout.Layout
}

// AssetFor is one agent file's contents, rendered whatever the asset is named.
// It is how the plugins and the hook registrations get the installed binary's
// path compiled in rather than reading it from an environment the host
// controls.
func AssetFor(target *Target, file File, configDir string) ([]byte, error) {
	if configDir == "" {
		configDir = hostlayout.DefaultConfigDir
	}
	return RenderData(file.Asset, PluginData{
		// The compiled path, as uninstall and reload resolve it: a post-install
		// command reads the binary where the install put it.
		BinDir:        hostlayout.DefaultBinDir,
		Agent:         target.Name,
		Family:        target.FamilyName(),
		Path:          file.Path,
		DefaultExport: file.DefaultExport,
		Layout:        RuleLayout(configDir),
	})
}

// OneSectionPerFile drops a file an earlier one in the list already resolves
// to, so a tree whose CLAUDE.md is a link to its AGENTS.md is written once.
//
// Only these files. Every instructions file in a tree carries the same
// credentials section, so one standing in for two writes the same bytes to the
// same place and loses nothing. Two agents' settings files are each written for
// the agent that reads them, and a link between those is refused rather than
// deduplicated: see oneFileTwice.
//
// A path that cannot be resolved keeps its own name, so a dangling link stays
// in the list and is refused by RefuseUnwritable, which says why.
//
// The first name wins, which puts the section in the tree's own file and leaves
// the link pointing at it.
func OneSectionPerFile(files []SectionTarget) []SectionTarget {
	out := make([]SectionTarget, 0, len(files))
	claimed := map[string]bool{}
	for _, file := range files {
		name := file.Path
		if resolved, err := filepath.EvalSymlinks(name); err == nil {
			name = resolved
		}
		if claimed[name] {
			continue
		}
		claimed[name] = true
		out = append(out, file)
	}
	return out
}

// SectionTarget is one file the section goes into, with what heads it where
// this creates it. See sectionFile.
type SectionTarget struct {
	Path string
	Head string
}

// CredentialsSection is the section `enrol` writes into a tree.
// Rendered rather than shipped as it is, for one paragraph: what an agent is
// told about waiting for an escalation only holds on a host installed with
// --allow-sudo, and on any other host it describes a refusal that never
// happens.
func CredentialsSection(allowSudo bool) (string, error) {
	body, err := RenderData("agent/instructions.md.snippet",
		struct{ AllowSudo bool }{AllowSudo: allowSudo})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}

// TreeInstructionsFile is the file a tree carries the credentials section in:
// the first name an agent reads that is already there, and the first name when
// none is. Answered from the tree alone, so `doctor` can ask about a tree it
// did not enrol.
func TreeInstructionsFile(dir string) string {
	for _, name := range InstructionFiles {
		path := filepath.Join(dir, name)
		if hostfs.Exists(path) {
			return path
		}
	}
	return filepath.Join(dir, InstructionFiles[0])
}

// BinaryName is what the installed program is called, wherever it is installed.
// Spelled once: a merge recognises faramir's own entries in an agent's config by
// the program they invoke.
const BinaryName = "faramir"

// Asset reads one embedded file.
func Asset(assetPath string) ([]byte, error) {
	data, err := faramir.Assets.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("embedded asset %s: %w", assetPath, err)
	}
	return data, nil
}

// HomeSection is the section `init` writes into a home. Rendered rather than
// shipped as it is, for the escalation half: a host that granted no sudo would
// otherwise be telling an agent how to ask for something it cannot have.
//
// It names no path this install decides, the rules it explains being rendered
// into each agent's own config from protectedpaths.go.
func HomeSection(allowSudo bool) (string, error) {
	body, err := RenderData("agent/instructions.home.md.snippet",
		struct {
			AllowSudo bool
		}{AllowSudo: allowSudo})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}
