package guard

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"sync"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
)

// wrapScript is the shell fragment the rewrite sources. Absolute: the
// rewritten string runs in the agent's working directory.
func wrapScript() string {
	if v := os.Getenv("FARAMIR_WRAP"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/wrap.sh"
}

// patternsFile is rendered per install, so it lives in libexec rather than
// under /etc/faramir. Missing, the fallback list below is used.
func patternsFile() string {
	if v := os.Getenv("FARAMIR_DENY_PATTERNS"); v != "" {
		return v
	}
	return "/usr/local/libexec/faramir/deny-patterns.txt"
}

// defaultInstallPaths is what an install at the compiled defaults occupies, in
// the order agentcfg.Dirs renders them.
//
// Written here rather than taken from internal/install, which cannot be
// imported: this package's own tests import that one, so the arrow only points
// one way. The rules generated from these have to equal the ones the shipped
// file carries at the same defaults, which TestTheFallbackMatchesTheShippedFile
// holds them to.
var defaultInstallPaths = []string{
	`/etc/faramir`,
	`/etc/faramir/secrets`,
	`/var/log/faramir`,
	`/usr/local/libexec/faramir`,
	`/var/lib/faramir-broker`,
	`/var/lib/faramir-keeper`,
	`/var/lib/faramir-exec`,
}

// fallback is used if the patterns file is missing, so a broken install still
// fails closed. Keep it in step with agent/hooks/deny-patterns.txt.
//
// A host whose config was moved by --config-dir is covered by configDirRules
// instead, which builds the same five rules for the path the config actually
// has. What this cannot carry either way is what the host declares: a
// [[secret.block]] entry is in the rendered file and nowhere else, so a host
// running on the fallback is a host running on faramir's own paths alone.
var fallback = fallbackPatterns()

// fallbackOwn is faramir's own: its binary, the files an enrolment installs,
// and the commands that act on the install rather than through it. Flattened
// from the catalogue's action rules, which is where they are spelled, in the
// shipped file's order: TestTheFallbackMatchesTheShippedFile compares the two
// line by line.
var fallbackOwn = denyrules.GuardRules(denyrules.ActionRules())

// ActionPatterns is what the guard refuses for what a command does rather than
// for what it points at: the commands that act on faramir's own install, and
// writes to the files an enrolment installs.
//
// Exported for `faramir block ls`, which lists them beside the entries this
// host declares. Nothing else could be asked what they are: an agent meets one
// as a refusal naming the rule that matched, never the set, so a rule that
// covers something reads exactly like one that does not.
//
// Not the path rules, which are generated per install from the same set the
// agents' own deny rules come from, and are already listed as the entries they
// were generated from.
// Without the kind marker. The group is how a refusal picks its message, not
// part of what the rule matches, and an operator reading the listing is being
// shown the rule: left on, every row opens with `(?P<ownaction>` and sorts by
// that rather than by the rule.
func ActionPatterns() []string {
	out := make([]string, 0, len(fallbackOwn))
	for _, rule := range fallbackOwn {
		out = append(out, unmarked(rule))
	}
	return out
}

// unmarked is one rendered rule with its kind group taken back off. Every rule
// GuardRules writes is KindMarker(kind) + pattern + ")", so the group is the
// prefix and the last byte; a rule carrying no marker is returned as it is.
func unmarked(rule string) string {
	for _, kind := range denyrules.Kinds() {
		marker := denyrules.KindMarker(kind)
		if strings.HasPrefix(rule, marker) && strings.HasSuffix(rule, ")") {
			return rule[len(marker) : len(rule)-1]
		}
	}
	return rule
}

// fallbackPatterns assembles the list in the shipped file's own order, which
// TestTheFallbackMatchesTheShippedFile compares line by line.
func fallbackPatterns() []string {
	subjects := make([]string, 0, len(defaultInstallPaths))
	for _, dir := range defaultInstallPaths {
		subjects = append(subjects, denyrules.Dir(dir))
	}
	// fallbackOwn first: a line can match both, and the rule that says something
	// more specific than "this path is in the blocks or the links" is the one
	// worth reporting.
	out := append([]string{}, fallbackOwn...)
	return append(out, denyrules.NamingAs(denyrules.KindOwn, subjects)...)
}

type compiled struct {
	source string
	re     *regexp.Regexp
}

// configDir is where this host's config, secrets and keys actually are, taken
// from the same place the daemons take it, so an install moved with
// --config-dir moves what these rules refuse.
func configDir() string {
	path := os.Getenv("FARAMIR_CONFIG")
	if path == "" {
		path = config.DefaultConfigPath
	}
	return filepath.Dir(path)
}

// configDirRules refuses reads and writes of one directory, whatever it is
// called: the same three shapes the literal rules use, so a moved install is
// covered the way /etc/faramir is.
func configDirRules(dir string) []string {
	return denyrules.NamingAs(denyrules.KindOwn,
		[]string{denyrules.DirUnder(guardHome(), dir)})
}

// guardHome is what a tilde in the command being judged stands for. This runs
// as the account the coding agent runs as, so $HOME is that account's own and
// is the home the command would have been expanded against.
func guardHome() string {
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		return ""
	}
	return home
}

// named reports whether the list already carries a rule about this directory,
// which the rendered file does for the install it was rendered for.
//
// The subject as it would be generated, not the quoted path: a path is a
// substring of every path that starts the same way, so a config at
// /var/lib/faramir would have been read as already named by a rule about
// /var/lib/faramir-broker, and skipped. What that skips is the only cover a
// moved config has.
func named(raw []string, dir string) bool {
	// The subject as the rendered file writes it, which for a directory under a
	// home is the alternation of the spellings a shell expands to it. Asking for
	// the plain form would miss it and append the same five rules again, on
	// every Bash call.
	subject := denyrules.DirUnder(guardHome(), dir)
	for _, pattern := range raw {
		if strings.Contains(pattern, subject) {
			return true
		}
	}
	return false
}

// The compiled deny list is cached on the pattern strings it was built from, so
// decide does not recompile every regexp on each Bash call. A different patterns
// file or config dir yields a different key and recompiles. Guarded by a mutex
// because the hook may be exercised concurrently by a test.
var (
	patternCacheMu  sync.Mutex
	patternCacheKey string
	patternCacheVal []compiled
)

// rawFilePatterns reads the deny-pattern lines from the patterns file, dropping
// blanks and comments. Nil when the file is missing or holds no rule.
func rawFilePatterns() []string {
	data, err := os.ReadFile(patternsFile())
	if err != nil {
		return nil
	}
	var lines []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			lines = append(lines, line)
		}
	}
	return lines
}

// withConfigDir appends the rules for a moved config dir. After the list, not
// before it: the file replaces the list wholesale, so a rule appended first is
// discarded, and the subjects are generated per install, so a config moved after
// the rules were rendered is covered by this and nothing else. Only for a
// directory the list does not already name, to avoid a duplicate rule.
func withConfigDir(raw []string) []string {
	if dir := configDir(); dir != "" && dir != "/" && !named(raw, dir) {
		return append(slices.Clone(raw), configDirRules(dir)...)
	}
	return raw
}

// compilePatterns compiles each pattern the way denyrules says one is read.
// complete is false when any line did not compile.
//
// Once per guard process, which is once per tool call: the cache above lives
// only as long as this one. Compilation is linear in the file's bytes at
// roughly 100ns each, so at 170 declared paths it is about 10ms and the
// matching that follows is 24us. What would cut it is not compiling the path
// rules at all where no literal in them appears in the command, which needs a
// list of those literals rendered beside the patterns: a second artifact an
// install can get out of step with the first, and a redesign rather than a
// change here.
func compilePatterns(raw []string) (out []compiled, complete bool) {
	complete = true
	out = make([]compiled, 0, len(raw))
	for _, pattern := range raw {
		re, err := denyrules.Compile(pattern)
		if err != nil {
			complete = false
			continue
		}
		out = append(out, compiled{source: pattern, re: re})
	}
	return out, complete
}

func loadPatterns() []compiled {
	fileLines := rawFilePatterns()
	usingFile := len(fileLines) > 0
	raw := fallback
	if usingFile {
		raw = fileLines
	}
	raw = withConfigDir(raw)

	key := strings.Join(raw, "\n")
	patternCacheMu.Lock()
	defer patternCacheMu.Unlock()
	if key == patternCacheKey && patternCacheVal != nil {
		return patternCacheVal
	}

	out, complete := compilePatterns(raw)
	if usingFile && !complete {
		// A bad line must not be dropped in silence: report it so the operator
		// knows a rule they wrote is not in force. The lines around it still stand.
		fmt.Fprintln(os.Stderr,
			"faramir guard: a line in the deny-patterns file does not compile; skipping it")
	}
	if usingFile && len(out) == 0 {
		// Nothing in the file compiled, so running with an empty list would refuse
		// nothing. Fall back to the built-in rules, which still cover faramir's own
		// paths, so a wholly broken file leaves the guard no weaker than a missing
		// one does.
		out, _ = compilePatterns(withConfigDir(fallback))
	}
	patternCacheKey, patternCacheVal = key, out
	return out
}
