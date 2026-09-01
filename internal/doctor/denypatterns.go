package doctor

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// diagnoseDenyPatterns checks the shipped deny list was rendered for this
// install: a list naming a directory nothing uses refuses reads of a secrets
// directory that is not there and passes every read of the one that is.
// uncompilable is the rules the hook would skip, in the file's own order. The
// hook compiles each with the same case-insensitive prefix, so this asks the
// question the way the hook answers it rather than a near version of it.
func uncompilable(rules []string) []string {
	var out []string
	for _, rule := range rules {
		if _, err := denyrules.Compile(rule); err != nil {
			out = append(out, rule)
		}
	}
	return out
}

func diagnoseDenyPatterns(report *Report, opts Options) {
	reportDenyPatterns(report, opts, filepath.Join(hostlayout.DefaultLibexecDir, "deny-patterns.txt"))
}

// reportDenyPatterns is the check against a path already chosen, so a test can
// put a rendered file somewhere it may write.
func reportDenyPatterns(report *Report, opts Options, path string) {
	body, err := os.ReadFile(path)
	if err != nil {
		report.addf("deny patterns", StatusFailed, "%s is missing, so the hook refuses "+
			"nothing: %v", path, err)
		return
	}
	// Interpolated quoted, so the comparison is against that form.
	if !strings.Contains(string(body), regexp.QuoteMeta(opts.ConfigDir)) {
		report.addf("deny patterns", StatusFailed, "%s does not name %s, so it was copied "+
			"from another install rather than rendered for this one", path, opts.ConfigDir)
		return
	}
	// Every declared command, which nothing else asks about. The blocked paths
	// check compares entries against the agents' own rule files, and a command
	// entry is in none of them: the guard's file is the whole of where one is
	// enforced, so a command missing from it is an entry doing nothing at all.
	//
	// The rendered rule rather than the words, which is what the file carries.
	var missing []string
	for _, entry := range agentcfg.ConfiguredBlocked(opts.ConfigDir) {
		if entry.Command == "" {
			continue
		}
		if !strings.Contains(string(body), agentcfg.BlockedCommandRule(entry.Command)) {
			missing = append(missing, entry.Command)
		}
	}
	if len(missing) > 0 {
		report.addf("deny patterns", StatusFailed, "%s does not carry %d declared command(s), so they are refused by nothing: %s. "+
			"`faramir init` renders the file again", path, len(missing), strings.Join(missing, ", "))
		return
	}
	// And the rest of it, against a re-render from this install's own layout.
	// The file is generated, so what it should hold is computable, and the
	// alternative is a check that asks only whether one path appears in it: the
	// render-on-add hole survived exactly that far.
	//
	// Rule lines alone, comments and blanks dropped, so a reflowed comment is not
	// reported as drift. A rule the host is missing refuses less than this
	// install asks for and fails; one it has spare refuses more, which is untidy
	// rather than unguarded, and warns.
	want := ruleLines(renderedDenyPatterns(opts.ConfigDir))
	if len(want) == 0 {
		report.addf("deny patterns", StatusOK, "%s names this install's directories "+
			"and every command it declares; what else it should hold could not be "+
			"rendered to compare", path)
		return
	}
	have := ruleLines(string(body))
	// Before the comparison, because a re-render compares the file to itself and
	// so agrees with a rule that no longer works. The hook skips a pattern that
	// will not compile rather than failing every command over it, which is the
	// right answer there and leaves the loss silent: what should have been three
	// rules is however many of them compiled.
	if broken := uncompilable(have); len(broken) > 0 {
		report.addf("deny patterns", StatusFailed, "%d of the %d rule(s) in %s will not compile, and the hook skips those, so each "+
			"refuses nothing: %s. A control character in an entry breaks the rule it renders; "+
			"`faramir block ls --declared` names them",
			len(broken), len(have), path, firstFew(broken))
		return
	}
	absent, spare := diffRuleLines(want, have)
	switch {
	case len(absent) > 0:
		report.addf("deny patterns", StatusFailed, "%s is missing %d of the %d rule(s) "+
			"this install renders, so the hook refuses less than the config asks "+
			"for: %s. `faramir init` renders it again",
			path, len(absent), len(want), firstFew(absent))
	case len(spare) > 0:
		report.addf("deny patterns", StatusWarn, "%s carries %d rule(s) this install does not render: %s. Extra refusals, so untidy "+
			"rather than unguarded; `faramir init` rewrites the file", path, len(spare), firstFew(spare))
	default:
		report.addf("deny patterns", StatusOK, "%s is what this install renders: %d "+
			"rule(s), naming its own directories and every command it declares",
			path, len(want))
	}
}

// renderedDenyPatterns is what this install would write, or "" where it cannot
// be rendered. Empty rather than an error: the checks above have already said
// whether the file is there, and a re-render that fails is this command's
// problem rather than the host's.
func renderedDenyPatterns(configDir string) string {
	body, err := agentcfg.RenderDenyPatterns(agentcfg.RuleLayout(configDir))
	if err != nil {
		return ""
	}
	return string(body)
}

// ruleLines is the patterns in a rendered file: what the guard compiles, which
// is every line that is neither blank nor a comment.
func ruleLines(body string) []string {
	var out []string
	for line := range strings.SplitSeq(body, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// diffRuleLines is what one list holds that the other does not, both ways.
func diffRuleLines(want, have []string) (absent, spare []string) {
	inHave := make(map[string]bool, len(have))
	for _, rule := range have {
		inHave[rule] = true
	}
	inWant := make(map[string]bool, len(want))
	for _, rule := range want {
		inWant[rule] = true
		if !inHave[rule] {
			absent = append(absent, rule)
		}
	}
	for _, rule := range have {
		if !inWant[rule] {
			spare = append(spare, rule)
		}
	}
	return absent, spare
}

// firstFew names a few rules and says how many were left out. A rule is a
// regular expression and some are long, so a finding that printed every one
// would be a finding nobody reads.
func firstFew(rules []string) string {
	const show = 2
	if len(rules) <= show {
		return strings.Join(rules, "; ")
	}
	return fmt.Sprintf("%s; and %d more", strings.Join(rules[:show], "; "),
		len(rules)-show)
}
