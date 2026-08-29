package install

import (
	"os/user"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/denyrules"
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
// Everything an install writes is covered by installDirs, which renders the real
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
	return installDirs(ruleLayout(configDir))
}

// InstalledAccounts is faramir's three service accounts at the names this host
// uses, read off the installed units the way `doctor` and the rule renderer
// read them, and the standard name where a unit cannot be read.
//
// Exported for the caller that has to refuse them as answers to "which account
// is the operator". A compiled-in list is right about a default install and
// silently wrong about a renamed one, and being wrong there means recording a
// service account as the operator and rendering every path rule against its
// home.
//
// No config directory: these come from the units, whose paths this package
// already knows, and a host that renamed an account renamed it there.
func InstalledAccounts() []string {
	broker, _ := unitUser(brokerUnit)
	keeper, _ := unitUser(keeperUnit)
	exec, _ := unitUser(execUnit)
	return []string{
		orDefault(broker, DefaultBrokerUser),
		orDefault(keeper, DefaultKeeperUser),
		orDefault(exec, DefaultExecUser),
	}
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

// installDirs are the paths this install occupies, known only once it is laid
// out and rendered as literal directories rather than as patterns, so a config
// and store moved into a home are the ones refused.
//
// Defaults are filled in for a Layout that carries only some of them: an empty
// string would become a rule matching "" and then every path under it, which
// fails closed and still breaks the agent.
// orDefault is the value, or the fallback where it is unset.
func orDefault(value, fallback string) string {
	if value == "" {
		return fallback
	}
	return value
}

func installDirs(layout Layout) []string {
	if layout.ConfigDir == "" {
		layout.ConfigDir = DefaultConfigDir
	}
	if layout.LogDir == "" {
		layout.LogDir = DefaultLogDir
	}
	if layout.LibexecDir == "" {
		layout.LibexecDir = DefaultLibexecDir
	}
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
	// has to be told these are faramir's. Dropping them left `init-project`
	// refusing two of this install's five directories and enrolling the other
	// three, which hands a daemon's own home to the client group and regroups the
	// .ssh inside it. A renamed account is covered only where the caller carries
	// the name.
	for _, account := range []string{
		orDefault(layout.BrokerUser, DefaultBrokerUser),
		orDefault(layout.KeeperUser, DefaultKeeperUser),
		orDefault(layout.ExecUser, DefaultExecUser),
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
func linkedPaths(layout Layout) []string {
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
func blockedRulePaths(layout Layout) []string {
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

// perInstallPaths is every literal path this install names, linked and refused
// together, deduplicated across the two. A path may be both, and the agent rule
// files are merged rather than replaced, so a rule written twice is a rule
// nothing takes back out.
func perInstallPaths(layout Layout) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(layout.Links)+len(layout.Blocked))
	for _, path := range append(linkedPaths(layout), blockedRulePaths(layout)...) {
		if seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// The spellings. One function per matcher rather than one parameterised over
// them: the agents differ in what a wildcard crosses.

// claudeRules is the deny list Claude Code reads: one Read and one Edit rule
// per path, plus this install's own directories. Read and Edit take the same
// list: a value the agent cannot read is one it can still destroy.
func claudeRules(layout Layout) []string {
	var out []string
	add := func(pattern string) {
		out = append(out, "Read("+pattern+")", "Edit("+pattern+")")
	}
	for _, dir := range installDirs(layout) {
		add(dir + "/**")
	}
	for _, path := range perInstallPaths(layout) {
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
func agyRules(layout Layout) []string {
	var out []string
	add := func(target string) {
		out = append(out, "read_file("+target+")", "write_file("+target+")")
	}
	// The literal paths, each covering itself and anything below it.
	for _, dir := range installDirs(layout) {
		add(dir)
	}
	for _, path := range perInstallPaths(layout) {
		add(path)
	}
	return out
}

// pluginPatterns is the deny list the two plugin hosts read, which key a map by
// the pattern rather than listing rules. Same paths, their spelling.
func pluginPatterns(layout Layout) []string {
	out := make([]string, 0, len(layout.Blocked)+8)
	for _, dir := range installDirs(layout) {
		out = append(out, dir+"/*")
	}
	out = append(out, perInstallPaths(layout)...)
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

// commandRules is the protected set in the spelling the command guard needs: a
// reader, a writer or a redirection pointed at any of it.
//
// The fourth rendering, beside the three agent spellings, and the point of
// having one list. A rule refuses an agent's file tools and says nothing about
// `cat`, which is half of what an operator declaring a path would assume; the
// two entry points now name the same set because they are generated from it.
//
// The verbs come from internal/denyrules, which internal/guard builds the same
// rules from for a config directory the rendered file did not name.
func commandRules(layout Layout) []string {
	rules := denyrules.For(commandSubjects(layout))
	// The commands this host declares, which reach here and nowhere else: a
	// command is not a path, so no agent's file-tool rules can carry one.
	for _, entry := range layout.Blocked {
		if entry.Command == "" {
			continue
		}
		if rule := BlockedCommandRule(entry.Command); rule != "" {
			rules = append(rules, rule)
		}
	}
	// And the entries whose operator asked for any mention of them to be
	// refused, which is a rule with no verb in it. Added rather than replacing
	// the five: those are what explain a refusal, and a bare subject can say
	// only that the path was named.
	return append(rules, denyrules.Mentioning(strictSubjects(layout))...)
}

// strictSubjects is every declared file whose entry asks for any mention of
// it to be refused, blocked and linked together. Sorted, so the rendered file
// does not churn.
func strictSubjects(layout Layout) []string {
	home := agentHome(layout)
	var out []string
	for _, entry := range layout.Blocked {
		if !entry.Strict {
			continue
		}
		if entry.Path != "" {
			out = append(out, denyrules.DirUnder(home, entry.Path))
		}
	}
	for _, link := range layout.Links {
		if link.Strict && link.Path != "" {
			out = append(out, denyrules.DirUnder(home, link.Path))
		}
	}
	sort.Strings(out)
	return slices.Compact(out)
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

// commandSubjects is every protected thing as a regex fragment. Literal paths
// are quoted whole; a pattern becomes the same matcher pi compiles, without the
// path anchors: a command line carries a path inside other text, so what
// anchors it is the reader in front of it rather than the start of a string.
func commandSubjects(layout Layout) []string {
	out := make([]string, 0, len(layout.Blocked)+8)
	// This install's own directories, and the files it names as linked or
	// blocked, at the paths this host uses. Bounded, so that a rule about
	// /etc/faramir is about that directory and not about /etc/faramir-notes.md.
	home := agentHome(layout)
	for _, dir := range installDirs(layout) {
		out = append(out, denyrules.DirUnder(home, dir))
	}
	for _, path := range perInstallPaths(layout) {
		out = append(out, denyrules.DirUnder(home, path))
	}
	return out
}

// agentHome is the home the tilde in a command line stands for, and "" where
// this install does not know it. The rules are matched against a command the
// agent typed, and the agent runs as the operator, so it is that account's home
// rather than a daemon's.
func agentHome(layout Layout) string {
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
func RenderDenyPatterns(layout Layout) ([]byte, error) {
	return render("agent/hooks/deny-patterns.txt", layout)
}
