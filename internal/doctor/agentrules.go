package doctor

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// diagnoseAgentRules reports every agent and what is configured for it. The
// rules are what refuse the agent's file tools the operator's own key material
// -- ~/.ssh, ~/.config/sops and the like -- which no uid boundary reaches
// because the agent runs as the operator. `faramir init --agent` writes them;
// enrolling a tree does not.
//
// One row each, in use or not: which agents an operator runs cannot be inferred
// from a directory. Only rules missing from an agent in use is a fault.
func diagnoseAgentRules(report *Report, opts Options) {
	if opts.AgentUser == "" {
		report.unaskedf("agent rules", 1, "the agent account is not named, so what "+
			"each agent has in its home was not asked: run through sudo so SUDO_USER "+
			"carries it, or record the account with `faramir init --agent-user`")
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent rules", 1, "could not read %s's home, so what each "+
			"agent has there was not asked", opts.AgentUser)
		return
	}
	enrolled, stale := agentcfg.EnrolledAgents(opts.ConfigDir)
	reportAgentRules(report, home, enrolled)
	// A tree that has moved or been deleted since it was enrolled. Reported
	// rather than removed: an unmounted tree is not a deleted one.
	for _, tree := range stale {
		report.addf("agent rules", StatusWarn, "%s was enrolled for %s and is no "+
			"longer there, so that entry says nothing about this host. Re-run "+
			"`faramir enrol` where the tree is now, or ignore it",
			tree.Dir, strings.Join(tree.Agents, ", "))
	}
}

// reportAgentRules is diagnoseAgentRules against a home already resolved, every
// question being about files under a directory rather than about the passwd
// database. enrolled names the agents some tree was enrolled for, which the
// home cannot show: an enrolled agent may leave no trace in this account.
func reportAgentRules(report *Report, home string, enrolled []string) {
	for _, name := range agentcfg.Known() {
		target := agentcfg.Targets[name]
		var missing []string
		for _, file := range target.AccountFiles {
			if !hostfs.Exists(filepath.Join(home, file.Path)) {
				missing = append(missing, "~/"+file.Path)
			}
		}
		switch {
		case len(missing) == 0:
			report.addf("agent rules", StatusOK, "%s: %s", name,
				strings.Join(accountPaths(target), ", "))
		// The rules cover what this install writes and what a [[secret.link]] or
		// [[secret.block]] entry names, which is agentcfg's protected set. Said that
		// way rather than by naming a key elsewhere: a path faramir did not choose
		// is one it does not rule on, and a message that names one makes the
		// default look more protective than it is.
		case slices.Contains(enrolled, name):
			report.addf("agent rules", StatusFailed, "a tree is enrolled for %s and %s is not there, so its file tools are refused "+
				"nothing this install protects, and no uid boundary refuses them either. Run "+
				"`sudo faramir init --agent %s`", name, strings.Join(missing, ", "), name)
		case agentInUse(home, target):
			report.addf("agent rules", StatusFailed, "%s is in this home and %s is not, so its file tools are refused nothing this "+
				"install protects, and no uid boundary refuses them either. Run `sudo faramir "+
				"init --agent %s`",
				name, strings.Join(missing, ", "), name)
		default:
			report.addf("agent rules", StatusNA, "%s: nothing here, so nobody runs it "+
				"from this account", name)
		}
	}
}

// hookReachFiles are the settings files whose PreToolUse registration decides
// which tools reach the guard at all: the account-wide one and each enrolled
// tree's. Claude Code only, being the one agent whose registration ever carried
// a matcher narrower than every tool.
func hookReachFiles(home string, dirs []string) []string {
	paths := make([]string, 0, 1+len(dirs))
	paths = append(paths, filepath.Join(home, ".claude/settings.json"))
	for _, dir := range dirs {
		paths = append(paths, filepath.Join(dir, ".claude/settings.local.json"))
	}
	return paths
}

// hookMatchers is the matcher of every PreToolUse group in one settings file
// that runs faramir's guard, and whether the file could be read at all.
//
// An absent file returns nothing and read=true: what a missing file says is
// diagnoseAgentRules' question, and two checks reporting one missing file is one
// report too many. A file that is there and cannot be opened or parsed returns
// read=false, which is not the same answer and must not be reported as one: a
// run without sudo against another account's home reaches every settings file
// this way, and calling that a pass would pass the very host this check exists
// to catch.
func hookMatchers(path string) (matchers []string, read bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, os.IsNotExist(err)
	}
	var doc struct {
		Hooks struct {
			PreToolUse []struct {
				Matcher *string `json:"matcher"`
				Hooks   []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	if json.Unmarshal(data, &doc) != nil {
		return nil, false
	}
	var out []string
	for _, group := range doc.Hooks.PreToolUse {
		for _, h := range group.Hooks {
			if !strings.Contains(h.Command, "faramir guard") {
				continue
			}
			matcher := ""
			if group.Matcher != nil {
				matcher = *group.Matcher
			}
			out = append(out, matcher)
			break
		}
	}
	return out, true
}

// diagnoseHookReach asks which tools the registered hook is invoked for.
//
// A registration written before the guard refused paths matches "Bash" alone, so
// the file tools never reach it. That leaves them to the deny rules in the same
// file, which are applied in some of the agent's permission modes and not in
// others: a session started in bypassPermissions applies none of them, and a
// read of the age key is then refused by nothing but the file's own mode.
//
// Reported rather than repaired, an agent's settings being the operator's file:
// re-running the enrolment rewrites the matcher.
func diagnoseHookReach(report *Report, opts Options) {
	if opts.AgentUser == "" {
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		return
	}
	var dirs []string
	for _, tree := range agentcfg.ReadEnrolled(opts.ConfigDir) {
		if slices.Contains(tree.Agents, "claude") {
			dirs = append(dirs, tree.Dir)
		}
	}
	var narrow, unread []string
	for _, path := range hookReachFiles(home, dirs) {
		matchers, read := hookMatchers(path)
		if !read {
			unread = append(unread, path)
			continue
		}
		for _, matcher := range matchers {
			if matcher != "*" {
				narrow = append(narrow, fmt.Sprintf("%s (%q)", path, matcher))
			}
		}
	}
	// Before the pass, and not folded into it. A file that is there and could not
	// be read is the case this check exists for, seen from the outside: a stale
	// registration and an unreadable one look identical from here, and reporting
	// the second as the first is how a host that needs re-enrolling reads as done.
	if len(unread) > 0 && len(narrow) == 0 {
		report.unaskedf("hook reach", len(unread), "could not read %s, so which tools "+
			"the guard answers for was not asked: run through sudo, or as the account "+
			"that owns them", strings.Join(unread, ", "))
		return
	}
	if len(narrow) == 0 {
		report.addf("hook reach", StatusOK, "every registration of the guard answers "+
			"for all tools, so a file tool reaches it whatever permission mode the "+
			"agent is in")
		return
	}
	report.addf("hook reach", StatusFailed, "the guard is registered for some tools "+
		"and not others in %s, so its file tools reach the guard only through the "+
		"deny rules beside it, and a session in a permission mode that ignores those "+
		"is refused nothing. Re-run `sudo faramir init` for the account-wide one and "+
		"`faramir enrol` in the tree for the rest",
		strings.Join(narrow, ", "))
}

// agentInUse reports whether this agent is present in the home at all: its own
// directory, or any of the rules faramir writes for it. The home markers
// rather than the tree ones, so this agrees with `init --agent auto`.
func agentInUse(home string, target *agentcfg.Target) bool {
	for _, marker := range target.DetectHome {
		if hostfs.Exists(filepath.Join(home, marker)) {
			return true
		}
	}
	for _, file := range target.AccountFiles {
		if hostfs.Exists(filepath.Join(home, file.Path)) {
			return true
		}
	}
	return false
}

// accountPaths is an agent's account-wide files, for a finding that names them.
func accountPaths(target *agentcfg.Target) []string {
	out := make([]string, 0, len(target.AccountFiles))
	for _, file := range target.AccountFiles {
		out = append(out, "~/"+file.Path)
	}
	return out
}
