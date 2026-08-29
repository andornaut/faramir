package install

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/config"
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
func diagnoseAgentRuleDrift(report *DoctorReport, opts DoctorOptions) {
	if opts.AgentUser == "" {
		report.unaskedf("agent rule drift", 1, "the agent account is not named, so "+
			"the agent rule files were not read: run through sudo so SUDO_USER "+
			"carries it, or record the account with `faramir init --agent-user`")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent rule drift", 1, "could not read %s's home, so the agent "+
			"rule files were not read", opts.AgentUser)
		return
	}
	reportRuleDrift(report, home, opts.ConfigDir)
}

// reportRuleDrift is diagnoseAgentRuleDrift against a home already resolved, so
// a test can put one somewhere other than a real account's.
func reportRuleDrift(report *DoctorReport, home, configDir string) {
	// With every per-install path, or each is a rule faramir writes and this
	// render does not, which staleRules would report as drift to delete. Both
	// kinds: a blocked path is only ever a rule, so being told to delete it is
	// being told to undo the entry.
	layout := ruleLayout(configDir)

	var stale, unread []string
	read, ruleCount := 0, 0
	// One file two agents read is read once: see uncoveredIn.
	seen := map[string]bool{}
	for _, name := range knownAgents() {
		for _, file := range agentTargets[name].accountFiles {
			if file.noRules || seen[file.path] {
				continue
			}
			seen[file.path] = true
			path := filepath.Join(home, file.path)
			if !exists(path) {
				continue
			}
			current, err := renderAccount(file.asset, layout)
			if err != nil {
				continue
			}
			found, err := staleRules(path, current, configDir)
			if err != nil {
				unread = append(unread, fmt.Sprintf("~/%s (%v)", file.path, err))
				continue
			}
			read++
			ruleCount += len(found)
			if len(found) > 0 {
				// The file named once with its rules under it: "file: rule" reads as two
				// paths, where what is to be removed is the entry inside the file.
				stale = append(stale, fmt.Sprintf("in ~/%s: %s",
					file.path, strings.Join(found, ", ")))
			}
		}
	}

	if len(unread) > 0 {
		report.unaskedf("agent rule drift", len(unread), "could not read %s, so what "+
			"they carry was not compared with what faramir writes now",
			strings.Join(unread, ", "))
		return
	}
	if len(stale) == 0 {
		report.addf("agent rule drift", StatusOK, "%d agent rule file(s) carry nothing "+
			"faramir has stopped writing", read)
		return
	}
	report.addf("agent rule drift", StatusWarn, "%d rule(s) faramir no longer writes are still in place, left rather than deleted "+
		"because yours would look the same. Remove them from the file, not the file itself, "+
		"and only where they are not yours: %s", ruleCount, strings.Join(stale, "; "))
}

// diagnoseLinkedFiles asks whether the account-wide deny rules refuse every
// file a [[secret.link]] entry reads. `link add` renders both together, but a
// link written into the config by hand, or a run that stopped between the two,
// leaves a value in the redactor whose plaintext the agent may still open.
//
// Failed rather than a warning, unlike rule drift: a stale rule refuses more
// than the current list asks for, while this refuses less.
func diagnoseLinkedFiles(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	const name = "linked files"
	links := make([]string, 0, len(cfg.Secret.Links))
	for _, link := range cfg.Secret.Links {
		links = append(links, link.Path)
	}
	if len(links) == 0 {
		report.addf(name, StatusOK, "no [[secret.link]] entries are configured")
		return
	}
	denyRuleCoverage(report, opts, name, linkedFilesCheck, links, nil)
}

// diagnoseAgentCode: the plugin, extension and hook files under a home are
// what routes and refuses for the agents that have no enforcing rule file, and
// until now only their existence was asked. They are the operator's files and
// the agent runs as the operator, so one rewritten to nothing silently ends
// routing; compared against their own render, the way the deny patterns are.
func diagnoseAgentCode(report *DoctorReport, opts DoctorOptions) {
	const name = "agent code"
	if opts.AgentUser == "" {
		report.unaskedf(name, 1, "the agent account is not named, so whether its "+
			"plugin and hook files carry what `faramir init` writes was not asked: "+
			"run through sudo so SUDO_USER carries it, or record the account with "+
			"`faramir init --agent-user`")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(name, 1, "could not read %s's home, so its plugin and "+
			"hook files were not compared with what `faramir init` writes", opts.AgentUser)
		return
	}
	reportAgentCode(report, home, opts.ConfigDir)
}

// reportAgentCode is diagnoseAgentCode against a home already resolved.
func reportAgentCode(report *DoctorReport, home, configDir string) {
	const name = "agent code"
	layout := ruleLayout(configDir)
	seen := map[string]bool{}
	checked := 0
	var drifted, unread []string
	for _, agent := range knownAgents() {
		target := agentTargets[agent]
		for _, file := range target.accountFiles {
			// Exactly the files the rule checks skip: a registration or a program
			// rather than a rule list. Absent is `agent rules`' finding.
			if !file.noRules || seen[file.path] {
				continue
			}
			seen[file.path] = true
			path := filepath.Join(home, file.path)
			if !exists(path) {
				continue
			}
			onDisk, err := os.ReadFile(path)
			if err != nil {
				unread = append(unread, "~/"+file.path)
				continue
			}
			ours, err := renderData(file.asset, pluginData{
				BinDir:        DefaultBinDir,
				Agent:         target.name,
				Family:        target.familyName(),
				Path:          file.path,
				DefaultExport: file.defaultExport,
				Layout:        layout,
			})
			if err != nil {
				unread = append(unread, "~/"+file.path)
				continue
			}
			checked++
			same := bytes.Equal(onDisk, ours)
			if !same && file.merge {
				if merged, err := mergeJSON(onDisk, ours, readWrittenRules(configDir)[path]); err == nil {
					same = sameDocument(merged, onDisk)
				}
			}
			if !same {
				drifted = append(drifted, "~/"+file.path)
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
		report.addf(name, StatusFailed, "%d file(s) no longer carry what `faramir "+
			"init` writes, and each is the whole of what routes or refuses for its "+
			"agent: %s. Re-run `sudo faramir init`", len(drifted), strings.Join(drifted, ", "))
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
func denyRuleCoverage(report *DoctorReport, opts DoctorOptions, name string,
	check coverageCheck, paths []string, expressible func(file, subject string) bool) {
	counted := fmt.Sprintf(check.noun, len(paths))
	if opts.AgentUser == "" {
		report.unaskedf(name, len(paths), "the agent account is not named, so the "+
			"deny rules were not compared with the %s: run through "+
			"sudo so SUDO_USER carries it, or record the account with "+
			"`faramir init --agent-user`", counted)
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf(name, len(paths), "could not read %s's home, so the deny "+
			"rules were not compared with the %s", opts.AgentUser, counted)
		return
	}
	check.report(report, name, home, paths, expressible)
}

// report is the check against a home already resolved, so a test can put one
// somewhere other than a real account's.
func (c coverageCheck) report(report *DoctorReport, name, home string,
	paths []string, expressible func(file, subject string) bool) {
	counted := fmt.Sprintf(c.noun, len(paths))
	files, uncovered, unread := uncoveredIn(home, paths, expressible)
	// Before the coverage verdict: a rule file that could not be read is not
	// one anything vouched for, and a pass beside it would claim it.
	if len(unread) > 0 {
		report.addf(name, StatusFailed, "%s could not be read or parsed, so what "+
			"it refuses is unknown and the %s were not established there. Fix the "+
			"file, or re-run `sudo faramir init`", strings.Join(unread, ", "), counted)
		return
	}
	switch {
	case files == 0:
		report.unaskedf(name, len(paths), "no agent under %s keeps rules of its own, so "+
			"the %s were not looked for in one. What refuses them there is "+
			"the guard, from the rendered deny list, which `deny patterns` checks",
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
// expressible, where non-nil, says whether one file has a spelling for one
// subject at all: a path a file cannot be given a rule for is not missing from
// it, the enrolment having reported it unexpressible instead.
func uncoveredIn(home string, paths []string, expressible func(file, subject string) bool) (files int, uncovered, unread []string) {
	// One file two agents read is one file to check: the Antigravity family
	// shares its account-wide hook, and reporting it twice reads as two files
	// short of what they should carry.
	seen := map[string]bool{}
	for _, agent := range knownAgents() {
		for _, file := range agentTargets[agent].accountFiles {
			// A registration rather than a rule file. Read as one it names no
			// protected path, and every path would be reported unrefused.
			if file.noRules || seen[file.path] {
				continue
			}
			seen[file.path] = true
			path := filepath.Join(home, file.path)
			if !exists(path) {
				continue
			}
			onDisk, err := os.ReadFile(path)
			if err != nil {
				// A rule file that cannot be read is not one vouched for by its
				// siblings: what it refuses is unknown, which the caller reports
				// rather than skipping past.
				unread = append(unread, "~/"+file.path)
				continue
			}
			entries, err := denyEntries(onDisk)
			if err != nil {
				unread = append(unread, "~/"+file.path)
				continue
			}
			files++
			var missing []string
			for _, want := range paths {
				if expressible != nil && !expressible(file.path, want) {
					continue
				}
				if !named(entries, want) {
					missing = append(missing, want)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				// The file named once with the paths under it, as the drift report
				// does.
				uncovered = append(uncovered, fmt.Sprintf("in ~/%s: %s",
					file.path, strings.Join(missing, ", ")))
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
func diagnoseInstallRules(report *DoctorReport, opts DoctorOptions) {
	const name = "install rules"
	// The same layout the rules were rendered from, ruleLayout reading the
	// units, the config and its entries: a hand-built one left the per-install
	// half empty, so a moved audit log was asked about at a directory it does
	// not use.
	layout := ruleLayout(opts.ConfigDir)
	paths := append(installDirs(layout), perInstallPaths(layout)...)
	denyRuleCoverage(report, opts, name, installRulesCheck, paths, nil)
}

// diagnoseBlockedPaths asks whether the account-wide deny rules carry every
// [[secret.block]] entry, by path and by name alike. The rule is the entire
// content of one of these entries, so an entry the rules do not carry is an
// entry doing nothing at all.
//
// Failed rather than a warning, for the reason the linked-file check fails: a
// stale rule refuses more than the list asks for, while this refuses less.
func diagnoseBlockedPaths(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	const name = "blocked paths"
	// Both forms, each compared as it is written: the rendered rule carries the
	// pattern a name entry declared, so containment answers for one the way it
	// answers for a path.
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
	// The CLI's own settings file cannot express four of the five name-pattern
	// kinds, which the enrolment reports as unexpressible rather than rendering
	// a rule that refuses a different set: a subject it cannot be given is not
	// missing from it.
	agyDropped := map[string]bool{}
	for _, entry := range cfg.Secret.Blocked {
		if entry.Name == "" {
			continue
		}
		if blockedNameRule(entry.Name).kind != kindSuffix {
			agyDropped[entry.Blocks()] = true
		}
	}
	expressible := func(file, subject string) bool {
		return file != agySettingsFile || !agyDropped[subject]
	}
	// Whether the path is there is not asked. An entry for a key on an unmounted
	// volume is doing its job by being in the rules, and a check that failed on
	// the absence would fail every time the volume was unmounted.
	denyRuleCoverage(report, opts, name, blockedPathsCheck, paths, expressible)
}

// ruleLayout is what an agent's rule file is rendered against: this install's
// own directories, and the paths its config names as linked or refused. One
// function for both sides, so what `init-project` writes into a tree is what
// `doctor` re-renders to compare it with, and a re-render is not read as drift.
func ruleLayout(configDir string) Layout {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	layout := Layout{
		ConfigDir: configDir,
		Links:     configuredLinks(configDir),
		Blocked:   configuredBlocked(configDir),
	}
	// The service accounts, read off the installed units the way `doctor` reads
	// them, so a host that renamed one has its state directories rendered at the
	// names it uses. A unit that cannot be read leaves the account empty and
	// installDirs falls back to the standard name, which is what an install that
	// named nothing used.
	layout.BrokerUser, _ = unitUser(brokerUnit)
	layout.KeeperUser, _ = unitUser(keeperUnit)
	layout.ExecUser, _ = unitUser(execUnit)
	// And the agent's own account, for the same reason: a path under its home is
	// rendered in the spellings a shell expands to it, so a re-render that does
	// not know the home writes fewer rules than the host carries and reports the
	// difference as drift. Read from the config the install rendered from rather
	// than from the caller, so the comparison is against what that file says.
	layout.AgentUser = configuredAgentUser(configDir)

	// The rest of what the shipped pattern file names, so a re-render of it can
	// be compared with the installed one. Taken from the config where the config
	// has it and from the compiled defaults where nothing does: the log
	// directory is where the broker is told to append, the SSH key is what the
	// broker lends, and the binary and libexec directories are fixed at build
	// time and have no key of their own.
	layout.BinDir, layout.LibexecDir = DefaultBinDir, DefaultLibexecDir
	layout.LogDir = DefaultLogDir
	if cfg, err := config.Load(filepath.Join(configDir, "config.toml")); err == nil {
		if cfg.Audit.LogPath != "" {
			layout.LogDir = filepath.Dir(cfg.Audit.LogPath)
		}
		layout.SSHKey = cfg.Ssh.Key
	}
	return layout
}

// configuredLinks is every link the install names, or nothing when the config
// cannot be read: a config that does not load is reported by the check that
// loads it.
func configuredLinks(configDir string) []config.Link {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return nil
	}
	return cfg.Secret.Links
}

// configuredBlocked is every blocked path the install names, on the same
// terms as configuredLinks.
// configuredAgentUser is [server] agent_user as the installed config records
// it, and "" where the config cannot be read: installDirs and the rule
// rendering both skip an empty one, so a home missing from both sides of the
// comparison is not drift.
func configuredAgentUser(configDir string) string {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return ""
	}
	return cfg.Server.AgentUser
}

func configuredBlocked(configDir string) []config.BlockedPath {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return nil
	}
	return cfg.Secret.Blocked
}

// named reports whether any rule in a file names this path. Containment rather
// than equality, each agent spelling the same path its own way: Claude Code
// writes "Read(/path)" while the plugin hosts key on the path itself.
//
// The match ends at a path character, so a longer path does not vouch for a
// shorter one: with ~/.npmrc and ~/.npmrc-work both linked, a rule naming only
// the second must not report the first as refused.
func named(entries map[string]bool, path string) bool {
	for entry := range entries {
		for start := 0; ; {
			i := strings.Index(entry[start:], path)
			if i < 0 {
				break
			}
			i += start
			start = i + 1
			// Anchored on the left as well as the right: a path character before
			// the match means a rule about a longer name, so "**/my.env" must not
			// vouch for ".env" any more than ".npmrc-work" vouches for ".npmrc".
			if i > 0 && isPathRune(rune(entry[i-1])) {
				continue
			}
			rest := entry[i+len(path):]
			// The subtree spelling of this same path. A directory is rendered as
			// "<dir>/**" for Claude Code and "<dir>/*" for the plugin hosts, and
			// without this both read as a longer path and the rule that is there
			// reports as missing. A wildcard is what separates them from a sibling:
			// "/secrets/**" after "/etc/faramir" is a different directory and stays
			// unmatched, and "-notes" after it is stopped by isPathRune already.
			if strings.HasPrefix(rest, "/*") {
				return true
			}
			if rest == "" || !isPathRune(rune(rest[0])) {
				return true
			}
		}
	}
	return false
}

// isPathRune reports whether a byte could continue a filename, which is what
// decides whether a match was the whole path or a prefix of a longer one. The
// separators each agent wraps a path in -- ")", quotes, whitespace, a glob --
// are not path characters.
func isPathRune(r rune) bool {
	switch {
	case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9':
		return true
	}
	return strings.ContainsRune("-_.~+@,:/", r)
}

// staleRules is the entries in path that name something faramir manages and are
// not in what it writes now.
func staleRules(path string, current []byte, configDir string) ([]string, error) {
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
		if want[entry] || !looksManaged(entry, configDir) {
			continue
		}
		out = append(out, entry)
	}
	sort.Strings(out)
	return out, nil
}

// ruleEntries is every rule an agent's config states, in either shape these
// files use: a list of strings, as Claude Code writes its deny rules, and an
// object keyed by pattern, as the plugin hosts write theirs. Shape rather than
// a named path per agent, so an agent that moves its rules to another key is
// still read; a key whose value is not a decision is not a rule.
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

// denyEntries is the rules that refuse: strings inside an array under a "deny"
// key, and keys whose own value is "deny". ruleEntries above stays the wide
// set for staleRules, which asks about presence rather than direction;
// coverage asked with the wide set read an operator's own allow entry as a
// refusal of the path it grants.
func denyEntries(data []byte) (map[string]bool, error) {
	var root any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil, err
	}
	out := map[string]bool{}
	var walk func(node any, underDeny bool)
	walk = func(node any, underDeny bool) {
		switch value := node.(type) {
		case []any:
			for _, element := range value {
				if text, isString := element.(string); isString {
					if underDeny {
						out[text] = true
					}
					continue
				}
				walk(element, underDeny)
			}
		case map[string]any:
			for key, child := range value {
				if decision, isString := child.(string); isString {
					if decision == decisionDeny {
						out[key] = true
					}
					continue
				}
				walk(child, underDeny || key == decisionDeny)
			}
		}
	}
	walk(root, false)
	return out, nil
}

// decisions are the verdicts these files spell, and what tells a rule from
// ordinary configuration. "ask" and "allow" are here although faramir writes
// neither, what is read being somebody else's file as well as faramir's.
var decisions = []string{decisionDeny, "allow", "ask"}

// decisionDeny is the one verdict coverage counts; the other two are read only
// to tell a rule from ordinary configuration.
const decisionDeny = "deny"

// isDecision reports whether a value is a permission verdict rather than
// ordinary configuration, which is what makes its key a rule.
func isDecision(value string) bool {
	return slices.Contains(decisions, value)
}

// looksManaged reports whether an entry names something on faramir's list.
// Nothing here is a record of what earlier versions wrote, a stored list going
// stale the first time somebody edits the file, so this infers from the name: a
// rule naming a layout faramir has stopped using names it by that name.
//
// Generous in one direction and never the other: an operator's own rule
// refusing a path faramir also refuses is reported alongside the leftovers, the
// two being indistinguishable, and the finding says so. A rule about anything
// else is not reported at all.
//
// configDir is the install being examined rather than the default, so a stale
// rule naming a non-default directory still in use is found.
func looksManaged(entry, configDir string) bool {
	// Its own name: anything under a path with "faramir" in it is faramir's to ask
	// about, whatever layout put it there.
	if strings.Contains(entry, "faramir") {
		return true
	}
	for _, dir := range installDirs(Layout{ConfigDir: configDir}) {
		if strings.Contains(entry, dir) {
			return true
		}
	}
	return false
}
