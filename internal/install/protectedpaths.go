package install

import (
	"regexp"
	"sort"
	"strings"
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
type pathKind int

const (
	// kindName is an exact file name, wherever it appears: "age.key".
	kindName pathKind = iota
	// kindSuffix is a name ending this way: ".key" covers "deploy.key".
	kindSuffix
	// kindPrefix is a name starting this way: ".env" covers ".env.local" but
	// not "faramir.env", which holds refs and is meant to be read.
	kindPrefix
	// kindGlobName is a name with one wildcard inside it: "secrets*.yml".
	kindGlobName
	// kindDir is anything below a directory named by the tail of its path:
	// "sops/age/" covers ~/.config/sops/age/keys.txt.
	kindDir
)

// protectedPath is one rule, in the form every agent's spelling derives from.
type protectedPath struct {
	kind pathKind
	// value is the name, suffix, prefix, glob or directory tail.
	value string
	// why is what this covers, for the comment each rendering carries. Every
	// entry has one: a list of bare globs is a list nobody dares delete from.
	why string
}

// protectedPaths is the list itself, ordered by what it protects rather than
// alphabetically.
// What a protected path is, for the paths that share a description. Several
// patterns describe one kind of file, and the wording is what a refusal says.
const (
	descSopsFile = "a managed sops file"
	descSSHKey   = "an SSH private key"
)

var protectedPaths = []protectedPath{
	// The managed store, by the names sops files are given.
	{kindGlobName, "secrets*.yml", descSopsFile},
	{kindGlobName, "secrets*.yaml", descSopsFile},
	{kindSuffix, ".sops.yml", descSopsFile},
	{kindSuffix, ".sops.yaml", descSopsFile},
	{kindSuffix, ".sops.json", descSopsFile},
	{kindSuffix, ".vault", "an ansible-vault file"},
	{kindName, "vault.yml", "an ansible-vault file"},

	// The keys that decrypt it. An age key replaced is every managed file
	// unreadable, retroactively.
	{kindName, "age.key", "an age identity"},
	{kindDir, "sops/age/", "the age identities sops reads"},
	{kindDir, ".config/sops/", "sops' own configuration and keys"},

	// The operator's own credentials, which no uid boundary reaches: the agent
	// runs as the operator.
	{kindName, "id_rsa", descSSHKey},
	{kindName, "id_dsa", descSSHKey},
	{kindName, "id_ecdsa", descSSHKey},
	{kindName, "id_ed25519", descSSHKey},
	{kindSuffix, ".key", "a private key"},
	{kindSuffix, ".pem", "a private key or certificate"},
	{kindName, "credentials", "a credentials file"},
	// A dotfile rather than any name ending in those four characters:
	// faramir.env holds faramir:// refs and is meant to be read.
	{kindPrefix, ".env", "a dotenv file"},

	// This install's own, wherever --config-dir put it.
	{kindDir, ".config/faramir/", "faramir's configuration"},
}

// installDirs are the paths this install occupies, known only once it is laid
// out and rendered as literal directories rather than as patterns, so a config
// and store moved into a home are the ones refused.
//
// Defaults are filled in for a Layout that carries only some of them: an empty
// string would become a rule matching "" and then every path under it, which
// fails closed and still breaks the agent.
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
	return []string{
		layout.ConfigDir, layout.SecretsDir(), layout.LogDir, layout.LibexecDir,
	}
}

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

// refusedRulePaths is the files and directories [[secret.refuse]] entries name,
// as literal paths, sorted and deduplicated the way linkedPaths are. Named for
// the rules it renders, RefusedPaths being what lists the entries themselves.
//
// Each renders the path and the subtree under it, whether or not it is a
// directory today. What it is, is not asked: these rules have to be a function
// of the config alone. Asking the filesystem writes no subtree rule for a key
// on a volume that is not mounted, which is the case an entry is most often
// for, and re-renders a different set once it mounts, which the drift check
// reports as rules to delete. A subtree rule on a file matches nothing; a
// missing one on a directory leaves every key in it readable.
//
// A directory is rendered as a directory, so naming ~/.ssh refuses what is
// under it rather than only the name itself. Which it is, is asked of the
// filesystem: a path that is not there is rendered as a file, that being the
// narrower of the two, and a rule that turns out to cover one path too few is
// better than one covering a subtree nobody meant to name.
func refusedRulePaths(layout Layout) []string {
	seen := make(map[string]bool, len(layout.Refused))
	out := make([]string, 0, len(layout.Refused))
	for _, refused := range layout.Refused {
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
	out := make([]string, 0, len(layout.Links)+len(layout.Refused))
	for _, path := range append(linkedPaths(layout), refusedRulePaths(layout)...) {
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

// claudePatterns renders the list in Claude Code's glob spelling, where "**/"
// means "in any directory" and a plain "*" does not cross a separator, so a
// suffix needs one of each.
func claudePatterns() []string {
	out := make([]string, 0, len(protectedPaths))
	for _, p := range protectedPaths {
		switch p.kind {
		case kindName, kindGlobName:
			out = append(out, "**/"+p.value)
		case kindSuffix:
			out = append(out, "**/*"+p.value)
		case kindPrefix:
			out = append(out, "**/"+p.value+"*")
		case kindDir:
			out = append(out, "**/"+strings.TrimSuffix(p.value, "/")+"/**")
		}
	}
	return out
}

// pluginGlobs renders the list for the two plugin hosts, whose "*" matches any
// run of characters including separators, so one leading wildcard does the work
// of both "in any directory" and "any name ending this way".
func pluginGlobs() []string {
	out := make([]string, 0, len(protectedPaths)+1)
	for _, p := range protectedPaths {
		switch p.kind {
		case kindName, kindGlobName, kindSuffix:
			out = append(out, "*"+p.value)
		case kindPrefix:
			// Both forms: at the root of what is matched, and in a directory.
			out = append(out, p.value+"*", "*/"+p.value+"*")
		case kindDir:
			// Both forms again: whether these hosts' "*" crosses a separator is
			// undocumented. If it does, the second is redundant; if it does not,
			// the second is the one that matches.
			dir := strings.TrimSuffix(p.value, "/")
			out = append(out, "*"+dir+"/*", "*/"+dir+"/*")
		}
	}
	return out
}

// claudeRules is the deny list Claude Code reads: one Read and one Edit rule
// per path, plus this install's own directories. Read and Edit take the same
// list: a value the agent cannot read is one it can still destroy.
func claudeRules(layout Layout) []string {
	var out []string
	add := func(pattern string) {
		out = append(out, "Read("+pattern+")", "Edit("+pattern+")")
	}
	for _, pattern := range claudePatterns() {
		add(pattern)
	}
	for _, dir := range installDirs(layout) {
		add(dir + "/**")
	}
	for _, path := range perInstallPaths(layout) {
		add(path)
	}
	for _, path := range refusedRulePaths(layout) {
		// Both forms, without asking the filesystem: see refusedRulePaths.
		add(path + "/**")
	}
	return out
}

// pluginPatterns is the deny list the two plugin hosts read, which key a map by
// the pattern rather than listing rules. Same paths, their spelling.
func pluginPatterns(layout Layout) []string {
	out := pluginGlobs()
	for _, dir := range installDirs(layout) {
		out = append(out, dir+"/*")
	}
	out = append(out, perInstallPaths(layout)...)
	for _, path := range refusedRulePaths(layout) {
		out = append(out, path+"/*")
	}
	return out
}

// jsonLines renders items as the body of a JSON array: each quoted, indented,
// comma-separated, and no trailing comma. Here rather than in a template,
// where the last comma is a conditional per line.
func jsonLines(indent string, items []string) string {
	var b strings.Builder
	for i, item := range items {
		b.WriteString(indent)
		b.WriteString(jsonString(item))
		if i < len(items)-1 {
			b.WriteString(",\n")
		}
	}
	return b.String()
}

// jsonDenyMap renders items as the body of a JSON object mapping each to
// "deny", which is the shape the plugin hosts' permission blocks take.
func jsonDenyMap(indent string, items []string) string {
	var b strings.Builder
	for i, item := range items {
		b.WriteString(indent)
		b.WriteString(jsonString(item))
		b.WriteString(": \"deny\"")
		if i < len(items)-1 {
			b.WriteString(",\n")
		}
	}
	return b.String()
}

// jsFragments renders the list for an agent whose rules are applied by a plugin
// this installs, as JavaScript regex source.
func jsFragments() []string {
	out := make([]string, 0, len(protectedPaths))
	for _, p := range protectedPaths {
		q := regexp.QuoteMeta(p.value)
		switch p.kind {
		case kindName:
			// A whole path component: "credentials" must not match
			// "credentials.md".
			out = append(out, `(^|/)`+q+`$`)
		case kindSuffix:
			out = append(out, q+`$`)
		case kindPrefix:
			out = append(out, `(^|/)`+q)
		case kindGlobName:
			out = append(out, `(^|/)`+strings.Replace(q, regexp.QuoteMeta("*"), `[^/]*`, 1)+`$`)
		case kindDir:
			out = append(out, q)
		}
	}
	return out
}
