package doctor

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// Rules faramir wrote once and no longer writes.
//
// The account-wide rule files are merged rather than replaced, and a merge can
// only add: an entry is a bare string in an array or a key in an object, with
// nowhere to carry a marker saying who put it there. Removing one
// automatically would need to know which entries are faramir's, and an
// operator's own rule refusing the same path is indistinguishable from one left
// behind; a stored record of what was last written would go stale the first
// time somebody edits the file.
//
// So this reports and a human decides. A warning rather than a failure: the
// extra rules are refusals, so the file says more than the current list asks
// for rather than less.
func diagnoseAgentRuleDrift(report *Report, opts Options) {
	if opts.AgentUser == "" {
		report.unaskedf("agent rule drift", 1, "the agent account is not named, "+
			"so the agent rule files were not read. Run doctor through sudo (SUDO_USER "+
			"names the account), or record it with `faramir init --agent-user`")
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent rule drift", 1, "could not read %s's home, so the agent "+
			"rule files were not read", opts.AgentUser)
		return
	}
	reportRuleDrift(report, home, opts.ConfigDir)
}

// reportRuleDrift is diagnoseAgentRuleDrift against a home already resolved, so
// a test can put one somewhere other than a real account's.
func reportRuleDrift(report *Report, home, configDir string) {
	// With every per-install path, or each is a rule faramir writes and this
	// render does not, which staleRules would report as drift to delete. Both
	// kinds: a blocked path is only ever a rule, so being told to delete it is
	// being told to undo the entry.
	layout := agentcfg.RuleLayout(configDir)

	var stale, unread []string
	read, ruleCount := 0, 0
	// One file two agents read is read once: see uncoveredIn.
	seen := map[string]bool{}
	for _, name := range agentcfg.Known() {
		for _, file := range agentcfg.Targets[name].AccountFiles {
			if file.NoRules || seen[file.Path] {
				continue
			}
			seen[file.Path] = true
			path := filepath.Join(home, file.Path)
			if !hostfs.Exists(path) {
				continue
			}
			current, err := agentcfg.RenderAccount(file.Asset, layout)
			if err != nil {
				continue
			}
			found, err := agentcfg.StaleRules(path, current, configDir)
			if err != nil {
				unread = append(unread, fmt.Sprintf("~/%s (%v)", file.Path, err))
				continue
			}
			read++
			ruleCount += len(found)
			if len(found) > 0 {
				// The file named once with its rules under it: "file: rule" reads as two
				// paths, where what is to be removed is the entry inside the file.
				stale = append(stale, fmt.Sprintf("in ~/%s: %s",
					file.Path, strings.Join(found, ", ")))
			}
		}
	}

	if len(unread) > 0 {
		report.unaskedf("agent rule drift", len(unread), "could not read %s, so "+
			"they were not compared with what faramir writes now",
			strings.Join(unread, ", "))
		return
	}
	if len(stale) == 0 {
		report.addf("agent rule drift", StatusOK, "%d agent rule file(s) carry nothing "+
			"faramir has stopped writing", read)
		return
	}
	report.addf("agent rule drift", StatusWarn, "%d rule(s) faramir no longer "+
		"writes are still in place. They were left because yours would look the same. "+
		"Remove them from the file, not the file itself, and only where they are not "+
		"yours: %s", ruleCount, strings.Join(stale, "; "))
}

// diagnoseLinkedFiles asks whether the account-wide deny rules refuse every
// file a [[secret.link]] entry reads. `link add` renders both together, but a
// link written into the config by hand, or a run that stopped between the two,
// leaves a value in the redactor whose plaintext the agent may still open.
//
// Failed rather than a warning, unlike rule drift: a stale rule refuses more
// than the current list asks for, while this refuses less.
func diagnoseLinkedFiles(report *Report, opts Options, cfg *config.Config) {
	const name = "linked files"
	links := make([]string, 0, len(cfg.Secret.Links))
	for _, link := range cfg.Secret.Links {
		links = append(links, link.Path)
	}
	if len(links) == 0 {
		report.addf(name, StatusOK, "no [[secret.link]] entries are configured")
		return
	}
	denyRuleCoverage(report, opts, name, linkedFilesCheck, links)
}

// diagnoseAgentCode: the plugin, extension and hook files under a home are
// what routes and refuses for the agents that have no enforcing rule file, and
// until now only their existence was asked. They are the operator's files and
// the agent runs as the operator, so one rewritten to nothing silently ends
// routing; compared against their own render, the way the deny patterns are.
func diagnoseAgentCode(report *Report, opts Options) {
	const name = "agent code"
	if opts.AgentUser == "" {
		report.unaskedf(name, 1, "the agent account is not named, so its plugin "+
			"and hook files were not compared with what `faramir init` writes. Run doctor "+
			"through sudo (SUDO_USER names the account), or record it with `faramir init "+
			"--agent-user`")
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(name, 1, "could not read %s's home, so its plugin and "+
			"hook files were not compared with what `faramir init` writes", opts.AgentUser)
		return
	}
	reportAgentCode(report, home, opts.ConfigDir)
}

// reportAgentCode is diagnoseAgentCode against a home already resolved.
func reportAgentCode(report *Report, home, configDir string) {
	const name = "agent code"
	layout := agentcfg.RuleLayout(configDir)
	seen := map[string]bool{}
	checked := 0
	var drifted, unread []string
	for _, agent := range agentcfg.Known() {
		target := agentcfg.Targets[agent]
		for _, file := range target.AccountFiles {
			// Exactly the files the rule checks skip: a registration or a program
			// rather than a rule list. Absent is `agent rules`' finding.
			if !file.NoRules || seen[file.Path] {
				continue
			}
			seen[file.Path] = true
			path := filepath.Join(home, file.Path)
			if !hostfs.Exists(path) {
				continue
			}
			onDisk, err := os.ReadFile(path)
			if err != nil {
				unread = append(unread, "~/"+file.Path)
				continue
			}
			ours, err := agentcfg.RenderData(file.Asset, agentcfg.PluginData{
				BinDir:        hostlayout.DefaultBinDir,
				Agent:         target.Name,
				Family:        target.FamilyName(),
				Path:          file.Path,
				DefaultExport: file.DefaultExport,
				Layout:        layout,
			})
			if err != nil {
				unread = append(unread, "~/"+file.Path)
				continue
			}
			checked++
			same := bytes.Equal(onDisk, ours)
			if !same && file.Merge {
				if merged, err := agentcfg.MergeJSON(onDisk, ours, agentcfg.ReadWrittenRules(configDir)[path]); err == nil {
					same = sameDocument(merged, onDisk)
				}
			}
			if !same {
				drifted = append(drifted, "~/"+file.Path)
			}
		}
	}
	sort.Strings(drifted)
	sort.Strings(unread)
	switch {
	case len(unread) > 0:
		report.addf(name, StatusFailed, "%s could not be read or rendered, so "+
			"whether it still carries what `faramir init` writes is unknown",
			strings.Join(unread, ", "))
	case len(drifted) > 0:
		report.addf(name, StatusFailed, "%d file(s) no longer carry what "+
			"`faramir init` writes, and each is all that routes or refuses for its agent: "+
			"%s. Re-run `sudo faramir init`", len(drifted), strings.Join(drifted, ", "))
	case checked > 0:
		report.addf(name, StatusOK, "%d plugin and hook file(s) carry what "+
			"`faramir init` writes", checked)
	default:
		report.addf(name, StatusOK, "no plugin or hook files are installed here")
	}
}

// coverageCheck is the phrasing of one deny-rule coverage check; the mechanics
// are denyRuleCoverage's. noun counts the subject the check names, okThe is the
// article its OK line puts before the count, and failure is the one message
// that is genuinely the check's own, with a %s for the uncovered list.
type coverageCheck struct {
	noun    string
	okThe   string
	failure string
}

var linkedFilesCheck = coverageCheck{
	noun: "%d linked file(s)",
	failure: "a linked file is not refused to the agent's file tools, so its plaintext is one " +
		"read away: %s. `faramir init` renders the rules again",
}

var installRulesCheck = coverageCheck{
	noun:  "%d path(s) this install writes",
	okThe: "the ",
	failure: "a path this install writes is not refused by the agent's rules, so its file tools " +
		"can open the age key, the managed store or the audit log by name: %s. `sudo " +
		"faramir init --agent NAME` restores them",
}

var blockedPathsCheck = coverageCheck{
	noun: "%d blocked path(s)",
	failure: "a path this install refuses is not refused by the agent's rules, which is the " +
		"whole of what the entry does: %s. `faramir init` renders them again",
}

// denyRuleCoverage resolves the agent's home and compares the account-wide deny
// rules with paths, reporting under the check's own phrasing. The three checks
// that ask this differ only in that phrasing and in their failure line.
func denyRuleCoverage(report *Report, opts Options, name string,
	check coverageCheck, paths []string) {
	counted := fmt.Sprintf(check.noun, len(paths))
	if opts.AgentUser == "" {
		report.unaskedf(name, len(paths), "the agent account is not named, so "+
			"the deny rules were not compared with the %s. Run doctor through sudo "+
			"(SUDO_USER names the account), or record it with `faramir init --agent-user`", counted)
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(name, len(paths), "could not read %s's home, so the deny "+
			"rules were not compared with the %s", opts.AgentUser, counted)
		return
	}
	check.report(report, name, home, paths)
}

// report is the check against a home already resolved, so a test can put one
// somewhere other than a real account's.
func (c coverageCheck) report(report *Report, name, home string,
	paths []string) {
	counted := fmt.Sprintf(c.noun, len(paths))
	files, uncovered, unread := uncoveredIn(home, paths)
	// Before the coverage verdict: a rule file that could not be read is not
	// one anything vouched for, and a pass beside it would claim it.
	if len(unread) > 0 {
		report.addf(name, StatusFailed, "%s could not be read or parsed, so "+
			"what it refuses is unknown and the %s were not checked there. Fix the file, "+
			"or re-run `sudo faramir init`", strings.Join(unread, ", "), counted)
		return
	}
	switch {
	case files == 0:
		report.unaskedf(name, len(paths), "no agent under %s keeps rules of its "+
			"own, so the %s were not looked for in one. The guard refuses them there, "+
			"from the rendered deny list, which `deny patterns` checks",
			home, counted)
	case len(uncovered) == 0:
		report.addf(name, StatusOK, "%s%s are refused to the agent's "+
			"file tools in %d rule file(s)", c.okThe, counted, files)
	default:
		report.addf(name, StatusFailed, c.failure, strings.Join(uncovered, "; "))
	}
}

// uncoveredIn reports, for every account-wide rule file under home, which of
// paths no rule in it names, and how many files were read at all. Shared by the
// two checks that ask this: a linked file and a blocked path are rendered into
// the same rule files by the same step.
//
// A count of zero is "nothing to read here", not "nothing refuses these". An
// agent with no rule file of its own is refused by the guard instead, which
// reads the same paths out of the rendered deny list, so the callers report
// that case as unasked and name the check that does cover it.
func uncoveredIn(home string, paths []string) (files int, uncovered, unread []string) {
	// One file two agents read is one file to check: the Antigravity family
	// shares its account-wide hook, and reporting it twice reads as two files
	// short of what they should carry.
	seen := map[string]bool{}
	for _, agent := range agentcfg.Known() {
		for _, file := range agentcfg.Targets[agent].AccountFiles {
			// A registration rather than a rule file. Read as one it names no
			// protected path, and every path would be reported unrefused.
			if file.NoRules || seen[file.Path] {
				continue
			}
			seen[file.Path] = true
			path := filepath.Join(home, file.Path)
			if !hostfs.Exists(path) {
				continue
			}
			onDisk, err := os.ReadFile(path)
			if err != nil {
				// A rule file that cannot be read is not one vouched for by its
				// siblings: what it refuses is unknown, which the caller reports
				// rather than skipping past.
				unread = append(unread, "~/"+file.Path)
				continue
			}
			entries, err := agentcfg.DenyEntries(onDisk)
			if err != nil {
				unread = append(unread, "~/"+file.Path)
				continue
			}
			files++
			var missing []string
			for _, want := range paths {
				if !agentcfg.Named(entries, want) {
					missing = append(missing, want)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				// The file named once with the paths under it, as the drift report
				// does.
				uncovered = append(uncovered, fmt.Sprintf("in ~/%s: %s",
					file.Path, strings.Join(missing, ", ")))
			}
		}
	}
	return files, uncovered, unread
}

// diagnoseInstallRules asks whether the account-wide deny rules still carry the
// paths this install writes: the config directory, the store, the log, libexec
// and the three service accounts' own directories.
//
// Apart from diagnoseBlockedPaths, which asks the same question about the
// entries an operator declared, because the remedy differs: these are rendered
// from the layout on every `faramir init` and are restored by re-running it,
// where a declared entry is restored by `faramir block add`.
//
// Worth asking even though a mode refuses each of these to the agent's uid as
// well. The rules are the half that produces a corrective message naming
// `faramir run` instead of an EACCES the agent will try to work around, and until
// this check existed an agent's settings could drop them and every other check
// still passed.
func diagnoseInstallRules(report *Report, opts Options) {
	const name = "install rules"
	// The same layout the rules were rendered from, agentcfg.RuleLayout reading the
	// units, the config and its entries: a hand-built one left the per-install
	// half empty, so a moved audit log was asked about at a directory it does
	// not use.
	layout := agentcfg.RuleLayout(opts.ConfigDir)
	paths := append(agentcfg.Dirs(layout), agentcfg.PerInstallPaths(layout)...)
	denyRuleCoverage(report, opts, name, installRulesCheck, paths)
}

// diagnoseBlockedPaths asks whether the account-wide deny rules carry every
// [[secret.block]] path entry. The rule is the entire content of one of these
// entries, so an entry the rules do not carry is an entry doing nothing at all.
// A command entry is not asked about: it reaches the command guard and no
// agent's rule file, so it is not something these files could be short of.
//
// Failed rather than a warning, for the reason the linked-file check fails: a
// stale rule refuses more than the list asks for, while this refuses less.
func diagnoseBlockedPaths(report *Report, opts Options, cfg *config.Config) {
	const name = "blocked paths"
	// Compared as it is written: the rendered rule carries the path the entry
	// declared, so containment is the whole of the question.
	paths := make([]string, 0, len(cfg.Secret.Blocked))
	for _, entry := range cfg.Secret.Blocked {
		// A command entry reaches the command guard and no agent's rule file, so
		// it is not something these files could be missing.
		if entry.Command != "" {
			continue
		}
		paths = append(paths, entry.Blocks())
	}
	if len(paths) == 0 {
		report.addf(name, StatusOK, "no [[secret.block]] entries are configured")
		return
	}
	// Whether the path is there is not asked. An entry for a key on an unmounted
	// volume is doing its job by being in the rules, and a check that failed on
	// the absence would fail every time the volume was unmounted.
	denyRuleCoverage(report, opts, name, blockedPathsCheck, paths)
}
