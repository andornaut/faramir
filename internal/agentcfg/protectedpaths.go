package agentcfg

import (
	"cmp"
	"os/user"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// The paths an agent's file tools are refused, written once here and rendered
// into each agent's own syntax. A list per agent is a list that drifts, and a
// rule that covers nothing looks exactly like one that covers everything. So
// each entry says how it matches, and each agent's spelling is derived.
//
// This takes nothing away from the agent: values reach a command through the
// broker. What it refuses is reading or writing the material directly, which
// is the operator's own -- ~/.ssh and ~/.config/sops are covered by no uid
// boundary, the agent running as the operator.
// Nothing is compiled in, and that is the design rather than a list waiting to
// be filled.
//
// Everything an install writes is covered by Dirs, which renders the real
// paths out of the layout: the config directory wherever --config-dir put it,
// the store, the log and libexec. Those cover the age key, the broker's SSH key,
// the managed sops files and the audit log where they actually are, and a mode
// refuses each of them to the agent's uid as well.
//
// A compiled-in pattern would have to be about a file faramir does not write. It
// minted one age key, at <config-dir>/age.key, and the operator has a copy or an
// identity of their own only if they made one: `reader add` takes a public
// key and never learns where the private half sits. So a rule for
// ~/.config/sops/age or for "age.key" anywhere else guards a file that usually
// is not there, at a path this install did not choose, and makes the default
// look more protective than it is.
//
// What a host blocks beyond its own install is the operator's to name: `faramir
// block add`, or a configuration manager declaring what a fleet keeps. What that
// costs a host nobody declares anything on is in installing.md.

// InstalledDirs is what this install occupies, for a caller that has to show an
// operator what is blocked here without being able to say why each path is on
// the list. The rules are generated from it, so the listing and the rules
// cannot disagree.
func InstalledDirs(configDir string) []string {
	return Dirs(RuleLayout(configDir))
}

// InstalledDirCovering is the install's own directory that already blocks a
// path, and whether there is one. These are the only rules an entry cannot take
// back: they come out of the layout on every render, so removing an entry that
// named one leaves the path blocked and reporting "nothing removed" would read
// as the file becoming readable.
//
// For the operator who names a file rather than the directory, "stop blocking
// /etc/faramir/age.key" being the same request as naming /etc/faramir.
func InstalledDirCovering(configDir, path string) (string, bool) {
	if path == "" {
		return "", false
	}
	for _, dir := range InstalledDirs(configDir) {
		if path == dir || strings.HasPrefix(path, strings.TrimSuffix(dir, "/")+"/") {
			return dir, true
		}
	}
	return "", false
}

// Dirs are the paths this install occupies, known only once it is laid
// out and rendered as literal directories rather than as patterns, so a config
// and store moved into a home are the ones refused.
//
// Defaults are filled in for a Layout that carries only some of them: an empty
// string would become a rule matching "" and then every path under it, which
// fails closed and still breaks the agent.

func Dirs(layout hostlayout.Layout) []string {
	if layout.ConfigDir == "" {
		layout.ConfigDir = hostlayout.DefaultConfigDir
	}
	if layout.LogDir == "" {
		layout.LogDir = hostlayout.DefaultLogDir
	}
	if layout.LibexecDir == "" {
		layout.LibexecDir = hostlayout.DefaultLibexecDir
	}
	// The secrets directory is named beside the config directory that holds it,
	// though the regex rules cover it either way. The agent renderers do not
	// agree: one spells a directory `<dir>/*`, which reaches the files in it and
	// none below, so this entry is what carries the ciphertext there.
	dirs := make([]string, 0, 7)
	dirs = append(dirs,
		layout.ConfigDir, layout.SecretsDir(), layout.LogDir, layout.LibexecDir)
	// The three service accounts' own directories, which systemd creates from
	// StateDirectory= and the units use as those accounts' homes: the broker's
	// and the executor's .ssh among them. Derived from the account names the way
	// systemd derives them, so a --broker-user of another name moves with it.
	//
	// Defaulted like the directories above, and for the same reason: a caller
	// that knows where the config is and not what the accounts are called still
	// has to be told these are faramir's. Without them `init-project` enrols a
	// daemon's own home, which hands it to the client group and regroups the .ssh
	// inside it. A renamed account is covered only where the caller carries the
	// name.
	for _, account := range []string{
		cmp.Or(layout.BrokerUser, hostlayout.DefaultBrokerUser),
		cmp.Or(layout.KeeperUser, hostlayout.DefaultKeeperUser),
		cmp.Or(layout.ExecUser, hostlayout.DefaultExecUser),
	} {
		dirs = append(dirs, filepath.Join(stateDirRoot, account))
	}
	return dirs
}

// stateDirRoot is where systemd puts a StateDirectory=. Not a layout field:
// the units say StateDirectory=<account> and systemd decides the rest, so this
// is systemd's constant rather than an install's choice.
const stateDirRoot = "/var/lib"

// linkedPaths is the files [[secret.link]] entries name, as literal paths,
// sorted and deduplicated so two links into one file do not change what is
// written. An empty entry is dropped rather than rendered: in the plugin
// hosts' spelling it is a prefix of every path.
func linkedPaths(layout hostlayout.Layout) []string {
	seen := make(map[string]bool, len(layout.Links))
	out := make([]string, 0, len(layout.Links))
	for _, link := range layout.Links {
		path := link.Path
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// blockedRulePaths is the files and directories [[secret.block]] entries name,
// as literal paths, sorted and deduplicated the way linkedPaths are. Named for
// the rules it renders, BlockedPaths being what lists the entries themselves.
//
// Each renders the path and the subtree under it, whether or not it is a
// directory today, so naming ~/.ssh blocks what is under it rather than only
// the name itself. What it is, is not asked: these rules have to be a function
// of the config alone. Asking the filesystem writes no subtree rule for a key
// on a volume that is not mounted, which is the case an entry is most often
// for, and re-renders a different set once it mounts, which the drift check
// reports as rules to delete. A subtree rule on a file matches nothing; a
// missing one on a directory leaves every key in it readable.
//
// The subject is bounded rather than open, so a sibling whose name merely
// starts the same way is not covered: ~/.sshrc is not part of ~/.ssh.
func blockedRulePaths(layout hostlayout.Layout) []string {
	seen := make(map[string]bool, len(layout.Blocked))
	out := make([]string, 0, len(layout.Blocked))
	for _, refused := range layout.Blocked {
		path := refused.Path
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// PerInstallPaths is every literal path this install names, linked and refused
// together, deduplicated across the two. The agent rule files are merged rather
// than replaced, so a rule written twice is a rule nothing takes back out.
//
// Read off the catalogue rather than joined here, so the third entry point gets
// the same set as the other two. Which entry named a path, and which one wins
// where both did, is decided in one place; a union assembled here would be a
// second answer that agrees until the first one changes.
func PerInstallPaths(layout hostlayout.Layout) []string {
	rules := catalogue(layout)
	out := make([]string, 0, len(rules))
	for _, rule := range rules {
		if rule.Kind.DeclaredPath() {
			out = append(out, rule.Entry)
		}
	}
	sort.Strings(out)
	return out
}

// The spellings. One function per matcher rather than one parameterised over
// them: the agents differ in what a wildcard crosses.

// claudeRules is the deny list Claude Code reads: one Read and one Edit rule
// per path, plus this install's own directories. Read and Edit take the same
// list: a value the agent cannot read is one it can still destroy.
func claudeRules(layout hostlayout.Layout) []string {
	var out []string
	add := func(pattern string) {
		out = append(out, "Read("+pattern+")", "Edit("+pattern+")")
	}
	for _, dir := range Dirs(layout) {
		add(dir + "/**")
	}
	for _, path := range PerInstallPaths(layout) {
		add(path)
	}
	for _, path := range blockedRulePaths(layout) {
		// Both forms, without asking the filesystem: see blockedRulePaths.
		add(path + "/**")
	}
	return out
}

// agyRules is the deny list Antigravity's CLI reads, one read_file and one
// write_file rule per target.
//
// Both verbs, though the documented precedence makes one enough: a denied read
// blocks the write to the same path. Written anyway, so the file says what it
// refuses rather than relying on an implication, and so a release that drops
// the implication does not quietly open every path to a writer.
//
// A directory is named bare, and only bare. A path here covers the hierarchy
// under it, so the directory is the whole rule; the trailing wildcard the other
// agents' spellings need matches nothing at all here, not even the files
// directly inside, so writing one would put a rule in the file that refuses
// nothing and reads as though it refuses everything.
func agyRules(layout hostlayout.Layout) []string {
	var out []string
	add := func(target string) {
		out = append(out, "read_file("+target+")", "write_file("+target+")")
	}
	// The literal paths, each covering itself and anything below it.
	for _, dir := range Dirs(layout) {
		add(dir)
	}
	for _, path := range PerInstallPaths(layout) {
		add(path)
	}
	return out
}

// pluginPatterns is the deny list the two plugin hosts read, which key a map by
// the pattern rather than listing rules. Same paths, their spelling.
func pluginPatterns(layout hostlayout.Layout) []string {
	out := make([]string, 0, len(layout.Blocked)+8)
	for _, dir := range Dirs(layout) {
		out = append(out, dir+"/*")
	}
	out = append(out, PerInstallPaths(layout)...)
	for _, path := range blockedRulePaths(layout) {
		out = append(out, path+"/*")
	}
	return out
}

// jsonLines renders items as the body of a JSON array: each quoted, indented,
// comma-separated, and no trailing comma. Here rather than in a template,
// where the last comma is a conditional per line.
func jsonLines(indent string, items []string) string {
	return jsonBody(indent, "", items)
}

// jsonDenyMap renders items as the body of a JSON object mapping each to
// "deny", which is the shape the plugin hosts' permission blocks take.
func jsonDenyMap(indent string, items []string) string {
	return jsonBody(indent, `: "deny"`, items)
}

// jsonBody is both, suffix following each quoted item.
func jsonBody(indent, suffix string, items []string) string {
	var b strings.Builder
	for i, item := range items {
		b.WriteString(indent)
		b.WriteString(jsonString(item))
		b.WriteString(suffix)
		if i < len(items)-1 {
			b.WriteString(",\n")
		}
	}
	return b.String()
}

// commandRules is the protected set in the spelling the command guard needs:
// the paths, one rule per kind of entry that declared them, and the commands
// this host declares.
//
// The fourth rendering, beside the three agent spellings, and the point of
// having one list. A rule refuses an agent's file tools and says nothing about
// `cat`, which is half of what an operator declaring a path would assume; the
// two entry points now name the same set because they are generated from it.
//
// The spellings come from internal/denyrules, which internal/guard builds the
// same rules from for a config directory the rendered file did not name.
func commandRules(layout hostlayout.Layout) []string {
	return denyrules.GuardRules(catalogue(layout))
}

// catalogue is everything this install refuses, in the shape both tiers are
// built from. The broker builds its own from the config it started on, through
// the same denyrules.For, which is what keeps one tier from holding a rule the
// other has never heard of.
func catalogue(layout hostlayout.Layout) []denyrules.Rule {
	return denyrules.For(agentHome(layout), Dirs(layout), layout.SSHKey, config.SecretConfig{
		Blocked: layout.Blocked,
		Links:   layout.Links,
	})
}

// BlockedCommandRule is a declared command as the guard matches it: the words
// taken literally, any run of whitespace between them, and a word boundary at
// each end that has one.
//
// The words rather than a regular expression the operator writes. A pattern
// language here would be a second thing to get wrong in a file that decides
// what an agent may run, and the failure is silent in both directions: one that
// matches too much refuses ordinary work, and one that matches too little reads
// exactly like one that works.
func BlockedCommandRule(command string) string {
	return denyrules.CommandRule(command)
}

// agentHome is the home the tilde in a command line stands for, and "" where
// this install does not know it. The rules are matched against a command the
// agent typed, and the agent runs as the operator, so it is that account's home
// rather than a daemon's.
func agentHome(layout hostlayout.Layout) string {
	if layout.AgentUser == "" {
		return ""
	}
	u, err := user.Lookup(layout.AgentUser)
	if err != nil || u.HomeDir == "" || u.HomeDir == "/" {
		return ""
	}
	return u.HomeDir
}

// RenderDenyPatterns is the shipped pattern file as an install would write it,
// for a caller that has to read what a host would get. The rendering is the
// real one rather than a second copy of it: a test that built the file another
// way would be asserting on rules nobody installs.
func RenderDenyPatterns(layout hostlayout.Layout) ([]byte, error) {
	return Render("agent/hooks/deny-patterns.txt", layout)
}
