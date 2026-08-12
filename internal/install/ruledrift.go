package install

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
)

// Rules faramir wrote once and no longer writes.
//
// The account-wide rule files are merged rather than replaced, and a merge can
// only add: an entry is a bare string in an array or a key in an object, with
// nowhere to carry a marker saying who put it there.  So when the list changes
// spelling, what the last version wrote stays, and nothing removes it.
//
// Removing it automatically would need to know which entries are faramir's, and
// the only honest answer is that it cannot: an operator's own rule refusing the
// same path is indistinguishable from one of ours left behind.  A record of what
// was last written would go stale the first time somebody edits the file by hand
// or has an agent tidy it, and acting on a stale record is the one outcome worth
// avoiding, being the one that destroys somebody's configuration.
//
// So this reports and a human decides.  What it costs is a line in `faramir
// doctor` that an operator has to read; what it buys is that nothing faramir
// does not understand is ever deleted.
//
// The extra rules are refusals, so a host carrying them refuses more than the
// current list asks for.  That is why this is a warning and not a failure:
// nothing is unguarded, the file is merely untidy and says things faramir would
// not say now.
func diagnoseAgentRuleDrift(report *DoctorReport, opts DoctorOptions) {
	if opts.OperatorUser == "" {
		report.unasked("agent rule drift", 1, "the operator account is not named, so "+
			"the agent rule files were not read: pass --operator-user, or run through "+
			"sudo so SUDO_USER carries it")
		return
	}
	home, err := operatorHomeFor(opts.OperatorUser)
	if err != nil || home == "" {
		report.unasked("agent rule drift", 1, "could not read %s's home, so the agent "+
			"rule files were not read", opts.OperatorUser)
		return
	}
	reportRuleDrift(report, home, opts.ConfigDir)
}

// reportRuleDrift is diagnoseAgentRuleDrift against a home already resolved, so
// a test can put one somewhere other than a real account's.
func reportRuleDrift(report *DoctorReport, home, configDir string) {
	layout := Layout{ConfigDir: configDir}

	var stale, unread []string
	read := 0
	for _, name := range agentNames() {
		for _, file := range agentTargets[name].accountFiles {
			// Only the shared ones.  A file that is faramir's own is replaced whole
			// on every run, so it cannot carry anything faramir has stopped writing.
			if !file.merge {
				continue
			}
			path := filepath.Join(home, file.path)
			if !exists(path) {
				continue
			}
			current, err := render(file.asset, layout)
			if err != nil {
				continue
			}
			found, err := staleRules(path, current)
			if err != nil {
				unread = append(unread, fmt.Sprintf("~/%s (%v)", file.path, err))
				continue
			}
			read++
			for _, rule := range found {
				stale = append(stale, fmt.Sprintf("~/%s: %s", file.path, rule))
			}
		}
	}

	if len(unread) > 0 {
		report.unasked("agent rule drift", len(unread), "could not read %s, so what "+
			"they carry was not compared with what faramir writes now",
			strings.Join(unread, ", "))
		return
	}
	if len(stale) == 0 {
		report.add("agent rule drift", StatusOK, "%d agent rule file(s) carry nothing "+
			"faramir has stopped writing", read)
		return
	}
	report.add("agent rule drift", StatusWarn, "%d rule(s) faramir no longer writes "+
		"are still in place, left rather than deleted because an entry carries no "+
		"sign of who added it and yours would look the same. Remove them if they "+
		"are not yours: %s", len(stale), strings.Join(stale, ", "))
}

// staleRules is the entries in path that name something faramir manages and are
// not in what it writes now.
func staleRules(path string, current []byte) ([]string, error) {
	onDisk, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	have, err := ruleEntries(onDisk)
	if err != nil {
		return nil, err
	}
	want, err := ruleEntries(current)
	if err != nil {
		return nil, err
	}
	var out []string
	for entry := range have {
		if want[entry] || !looksManaged(entry) {
			continue
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out, nil
}

// ruleEntries is every rule an agent's config states, in either shape these
// files use: a list of strings, as Claude Code writes its deny rules, and an
// object keyed by pattern, as the plugin hosts write theirs.
//
// Shape rather than a named path per agent, so an agent that moves its rules to
// another key is still read.  A key whose value is not a decision is not a rule,
// which is what keeps "permission" and "read" out of the answer.
func ruleEntries(data []byte) (map[string]bool, error) {
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

// decisions are the verdicts these files spell, and what tells a rule from
// ordinary configuration: the key of one of these is a path being ruled on.
// "ask" and "allow" are here although faramir writes neither, because what is
// being read is somebody else's file as well as ours.
var decisions = []string{"deny", "allow", "ask"}

// isDecision reports whether a value is a permission verdict rather than
// ordinary configuration, which is what makes its key a rule.
func isDecision(value string) bool {
	return slices.Contains(decisions, value)
}

// looksManaged reports whether an entry names something on faramir's list.
//
// Deliberately generous in one direction and never the other: an operator's own
// rule refusing a path faramir also refuses is reported alongside the leftovers,
// because the two cannot be told apart, and the finding says so.  A rule about
// anything else is not reported at all, which is what keeps this from naming
// every line of somebody's settings.
func looksManaged(entry string) bool {
	for _, p := range protectedPaths {
		if strings.Contains(entry, strings.TrimSuffix(p.value, "/")) {
			return true
		}
	}
	for _, dir := range installDirs(Layout{}) {
		if strings.Contains(entry, dir) {
			return true
		}
	}
	return false
}
