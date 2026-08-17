package install

import (
	"regexp"
	"sort"
	"strings"
)

// The paths an agent's file tools are refused, written once here and rendered
// into each agent's own syntax.
//
// A list per agent is a list that drifts, and the drift is silent: a rule that
// covers nothing looks exactly like a rule that covers everything until
// somebody tests it, and one character is the difference.
//
// So each entry says how it matches rather than what it looks like in any one
// agent's config, and each agent's spelling is derived.  Adding a path is one
// line here and no lines anywhere else.
//
// This takes nothing away from the agent: values reach a command through the
// broker, which is the whole arrangement.  What it refuses is the agent reading
// or writing the material directly, which is the operator's own -- ~/.ssh and
// ~/.config/sops are not covered by any uid boundary, the agent running as the
// operator.
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
	// why is what this covers, for the comment each rendering carries.  Every
	// entry has one: a list of bare globs is a list nobody dares delete from.
	why string
}

// protectedPaths is the list itself.  Ordered by what it protects rather than
// alphabetically, so a reader can see the groups.
var protectedPaths = []protectedPath{
	// The managed store, by the names sops files are given.
	{kindGlobName, "secrets*.yml", "a managed sops file"},
	{kindGlobName, "secrets*.yaml", "a managed sops file"},
	{kindSuffix, ".sops.yml", "a managed sops file"},
	{kindSuffix, ".sops.yaml", "a managed sops file"},
	{kindSuffix, ".sops.json", "a managed sops file"},
	{kindSuffix, ".vault", "an ansible-vault file"},
	{kindName, "vault.yml", "an ansible-vault file"},

	// The keys that decrypt it.  An age key replaced is every managed file
	// unreadable, retroactively.
	{kindName, "age.key", "an age identity"},
	{kindDir, "sops/age/", "the age identities sops reads"},
	{kindDir, ".config/sops/", "sops' own configuration and keys"},

	// The operator's own credentials, which no uid boundary reaches: the agent
	// runs as the operator.
	{kindName, "id_rsa", "an SSH private key"},
	{kindName, "id_dsa", "an SSH private key"},
	{kindName, "id_ecdsa", "an SSH private key"},
	{kindName, "id_ed25519", "an SSH private key"},
	{kindSuffix, ".key", "a private key"},
	{kindSuffix, ".pem", "a private key or certificate"},
	{kindName, "credentials", "a credentials file"},
	// A dotfile rather than any name ending in those four characters:
	// faramir.env holds secret:// refs and is meant to be read.
	{kindPrefix, ".env", "a dotenv file"},

	// This install's own, wherever --config-dir put it.
	{kindDir, ".config/faramir/", "faramir's configuration"},
}

// installDirs are the paths this install occupies, which are known only once it
// is laid out.  Kept apart from protectedPaths because they are rendered as
// literal directories rather than as patterns: a config and store moved into a
// home are then the ones refused rather than the defaults.
// Defaults are filled in for a Layout that carries only some of them, which is
// every caller that built one to answer a different question.  Not cosmetic: an
// empty string here becomes a rule matching "" and then every path under it, so
// a half-filled Layout would produce a rule that refuses the whole filesystem.
// That fails closed, which is the safe direction and still a broken agent.
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

// linkedPaths is the files [[secrets.link]] entries name, as literal paths.
// Sorted and deduplicated so that two links into one file, or the order the
// drop-ins happened to be read in, do not change what is written.
//
// An empty entry is dropped rather than rendered: as a Claude rule "" would be a
// pattern matching nothing, but in the plugin hosts' spelling it is a prefix of
// every path, and a rule refusing the whole filesystem fails closed and still
// breaks the agent.
func linkedPaths(layout Layout) []string {
	seen := make(map[string]bool, len(layout.LinkedPaths))
	out := make([]string, 0, len(layout.LinkedPaths))
	for _, path := range layout.LinkedPaths {
		if path == "" || seen[path] {
			continue
		}
		seen[path] = true
		out = append(out, path)
	}
	sort.Strings(out)
	return out
}

// The spellings.  One function per matcher rather than one parameterised over
// them: the agents differ in what a wildcard crosses, and a knob for that is a
// knob somebody sets wrong.  Each of these is short enough to read against the
// agent's own documentation.

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
// run of characters including separators.  One leading wildcard therefore does
// the work of both "in any directory" and "any name ending this way", and a
// second would only widen it.
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
			// Both forms again, and deliberately: whether these hosts' "*" crosses
			// a separator is undocumented, and the list this replaces was written
			// both ways, so it is not a thing to have an opinion about.  If it
			// does cross, the second is redundant; if it does not, the second is
			// the one that matches.
			dir := strings.TrimSuffix(p.value, "/")
			out = append(out, "*"+dir+"/*", "*/"+dir+"/*")
		}
	}
	return out
}

// claudeRules is the deny list Claude Code reads: one Read and one Edit rule
// per path, plus this install's own directories.
//
// Read and Edit take the same list.  A value the agent cannot read is one it can
// still destroy, and an age key replaced is every managed file unreadable
// retroactively.
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
	for _, path := range linkedPaths(layout) {
		add(path)
	}
	return out
}

// pluginPatterns is the deny list the two plugin hosts read, which key a map by
// the pattern rather than listing rules.  Same paths, their spelling.
func pluginPatterns(layout Layout) []string {
	out := pluginGlobs()
	for _, dir := range installDirs(layout) {
		out = append(out, dir+"/*")
	}
	out = append(out, linkedPaths(layout)...)
	return out
}

// jsonLines renders items as the body of a JSON array: each quoted, indented,
// comma-separated, and no trailing comma.  Here rather than in a template
// because getting the last comma right in one is a conditional per line.
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
// this installs, as JavaScript regex source.  The same alternation, with the
// character classes JavaScript reads the same way every other flavour does.
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
