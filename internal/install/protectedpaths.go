package install

import (
	"fmt"
	"path/filepath"
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
// The age identities, and nothing else.
//
// Everything this install writes is refused by installDirs, which renders the
// real paths out of the layout: the config directory wherever --config-dir put
// it, the store, the log and libexec. Those cover the age key, the broker's SSH
// key, the managed sops files and the audit log where they actually are, and a
// mode refuses each of them to the agent's uid as well. A name rule for any of
// them would be a third statement of what two mechanisms already hold, written
// against the default path rather than this host's.
//
// What is left is what faramir does not install and no mode refuses: the
// operator's own age identity, which is a key to this store and sits in their
// home, and a copy of an age key anywhere else. Both are the agent's own uid's
// to read, so a deny rule is the only thing in the way.
//
// A credential faramir neither writes nor reads is the operator's to declare:
// `faramir refuse add`, or a configuration manager naming what a fleet keeps.
// What that costs a host nobody declares anything on is in installing.md.
var protectedPaths = []protectedPath{
	{kindName, "age.key", "an age identity"},
	{kindDir, "sops/age/", "the age identities sops reads"},
}

// refusedNameRules is the [[secret.refuse]] entries that named a pattern rather
// than a path, in the same form the built-in rules take, so the renderers below
// spell them the way they spell everything else.
//
// Which kind a pattern is comes from its shape, the way a .gitignore line's
// does. That is inference, and it is safe where the path-or-name choice is not:
// the shapes render to matchers that differ in breadth, and the operator is
// shown which one their pattern became before it is written. Getting it wrong
// refuses more or fewer files of the same kind; it cannot turn a rule into one
// that silently matches nothing, which is what an inferred path would do.
func refusedNameRules(layout Layout) []protectedPath {
	seen := make(map[string]bool, len(layout.Refused))
	out := make([]protectedPath, 0, len(layout.Refused))
	for _, refused := range layout.Refused {
		if refused.Name == "" || seen[refused.Name] {
			continue
		}
		seen[refused.Name] = true
		out = append(out, refusedNameRule(refused.Name))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].value < out[j].value })
	return out
}

// refusedNameRule is one pattern's kind and value. The order is the order the
// shapes exclude each other in: a trailing separator is a directory whatever
// else it holds, and a wildcard at one end is an open end rather than a name
// with a hole in it.
func refusedNameRule(name string) protectedPath {
	const why = "a path this install refuses"
	switch {
	case strings.HasSuffix(name, "/"):
		return protectedPath{kindDir, name, why}
	case strings.Count(name, "*") == 1 && strings.HasPrefix(name, "*"):
		return protectedPath{kindSuffix, strings.TrimPrefix(name, "*"), why}
	case strings.Count(name, "*") == 1 && strings.HasSuffix(name, "*"):
		return protectedPath{kindPrefix, strings.TrimSuffix(name, "*"), why}
	case strings.Contains(name, "*"):
		return protectedPath{kindGlobName, name, why}
	}
	return protectedPath{kindName, name, why}
}

// BuiltInRefusal is one compiled-in rule, for `faramir refuse ls`. The list is
// otherwise invisible: an agent meets it as a file tool refusing a path, and an
// operator had no way to ask what it covers short of tripping it, which reports
// the one rule that matched and not the set. A rule nobody can enumerate is one
// that gets declared a second time or reported as a gap.
type BuiltInRefusal struct {
	Kind  string `json:"kind"`
	Entry string `json:"entry"`
	Why   string `json:"why"`
}

// BuiltInRefusals is the compiled-in list, in the order it is written, which
// groups it by what it protects.
func BuiltInRefusals() []BuiltInRefusal {
	out := make([]BuiltInRefusal, 0, len(protectedPaths))
	for _, p := range protectedPaths {
		out = append(out, BuiltInRefusal{p.kind.String(), p.value, p.why})
	}
	return out
}

// BuiltInRefusalCovering is the compiled-in rule that already refuses a path,
// and whether there is one. For the operator who names the file rather than the
// pattern: "stop refusing ~/.ssh/id_rsa" is the same request as naming the
// built-in, and answering it with "that was not refused" would be false twice
// over.
func BuiltInRefusalCovering(path string) (BuiltInRefusal, bool) {
	for _, p := range protectedPaths {
		if p.covers(path) {
			return BuiltInRefusal{p.kind.String(), p.value, p.why}, true
		}
	}
	return BuiltInRefusal{}, false
}

// covers is whether this rule matches a path, in the terms each kind is written
// in. An approximation of what an agent's own matcher will do with the rendered
// spelling, and it is used to explain a refusal rather than to enforce one: the
// enforcement is the agent host's, on a rule this never sees applied.
func (p protectedPath) covers(path string) bool {
	base := filepath.Base(path)
	switch p.kind {
	case kindName:
		// A name may carry separators, so it is the tail of the path that answers
		// rather than the last segment alone.
		return path == p.value || strings.HasSuffix(path, "/"+p.value)
	case kindSuffix:
		return strings.HasSuffix(base, p.value)
	case kindPrefix:
		return strings.HasPrefix(base, p.value)
	case kindGlobName:
		matched, err := filepath.Match(p.value, base)
		return err == nil && matched
	case kindDir:
		dir := strings.TrimSuffix(p.value, "/")
		return strings.Contains(path, "/"+dir+"/") || strings.HasPrefix(path, dir+"/")
	}
	return false
}

// BuiltInRefusalFor is the compiled-in rule a pattern names, and whether there
// is one.
//
// Compared as the rule each becomes rather than as the string typed: "*.pem"
// and the built-in suffix ".pem" are one rule written two ways, while ".pem" on
// its own is a file of that name and a different rule. A comparison on the
// text would answer no to the first and yes to the second, both wrong.
func BuiltInRefusalFor(name string) (BuiltInRefusal, bool) {
	asked := refusedNameRule(name)
	for _, p := range protectedPaths {
		if p.kind == asked.kind && p.value == asked.value {
			return BuiltInRefusal{p.kind.String(), p.value, p.why}, true
		}
	}
	return BuiltInRefusal{}, false
}

// RefusedNameMatches says in a sentence what a name pattern will match, for the
// command that writes one and the listing that shows it. A pattern's breadth is
// the thing about it that goes unnoticed, so it is stated at the moment the
// operator can still change it.
func RefusedNameMatches(name string) string {
	rule := refusedNameRule(name)
	switch rule.kind {
	case kindSuffix:
		return fmt.Sprintf("any file whose name ends in %q, in any directory", rule.value)
	case kindPrefix:
		return fmt.Sprintf("any file whose name starts with %q, in any directory", rule.value)
	case kindGlobName:
		return fmt.Sprintf("any file whose name matches %q, in any directory", rule.value)
	case kindDir:
		return fmt.Sprintf("everything under any directory named %q",
			strings.TrimSuffix(rule.value, "/"))
	case kindName:
		// A name may carry separators, which is how a file inside a directory of a
		// given name is said: it is matched against the end of the path rather
		// than against the last segment of it.
		if strings.Contains(rule.value, "/") {
			return fmt.Sprintf("any path ending in %q, in any directory", rule.value)
		}
		return fmt.Sprintf("any file named %q, in any directory", rule.value)
	}
	return fmt.Sprintf("any file named %q, in any directory", rule.value)
}

// RefusedNameKind is the shape a pattern was read as, for a listing that shows
// the built-in rules and the declared ones side by side.
func RefusedNameKind(name string) string { return refusedNameRule(name).kind.String() }

// String names a kind the way the listing and the messages spell it.
func (k pathKind) String() string {
	switch k {
	case kindSuffix:
		return "suffix"
	case kindPrefix:
		return "prefix"
	case kindGlobName:
		return "glob"
	case kindDir:
		return "dir"
	case kindName:
		return "name"
	}
	return "name"
}

// protectedFor is every rule an install renders by name: the built-in list and
// the patterns this install declares. One list, so a declared pattern is spelled
// for each agent by the same code that spells a built-in, rather than by a
// second path through the renderers.
func protectedFor(layout Layout) []protectedPath {
	return append(append([]protectedPath{}, protectedPaths...), refusedNameRules(layout)...)
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
func claudePatterns(layout Layout) []string {
	rules := protectedFor(layout)
	out := make([]string, 0, len(rules))
	for _, p := range rules {
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
func pluginGlobs(layout Layout) []string {
	rules := protectedFor(layout)
	out := make([]string, 0, len(rules)+1)
	for _, p := range rules {
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
	for _, pattern := range claudePatterns(layout) {
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
	out := pluginGlobs(layout)
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
func jsFragments(layout Layout) []string {
	rules := protectedFor(layout)
	out := make([]string, 0, len(rules))
	for _, p := range rules {
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
