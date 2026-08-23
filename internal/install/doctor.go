package install

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sopsrule"
	"github.com/andornaut/faramir/internal/version"
)

// DoctorOptions names the accounts, groups and paths Diagnose examines.
type DoctorOptions struct {
	ConfigDir   string
	AgentUser   string
	ClientGroup string
	// The three service accounts, so the group audit does not report them as
	// unexpected members.
	BrokerUser string
	KeeperUser string
	ExecUser   string
	// SecretsGroup owns the managed sops files, defaulting to the keeper's own
	// group as install leaves it.
	SecretsGroup string

	// SecretsPatterns is the managed store, for the rule coverage check.
	// Diagnose fills it from the config it loads; a test may set it to reach the
	// check without a config. Empty leaves the check reported as unasked rather
	// than as a pass.
	SecretsPatterns []string

	// BrokerVersion is what the running broker reported, empty when it did not
	// answer.
	BrokerVersion string

	// BrokerBuild is which build of that version the broker is, empty from a
	// release and from a broker that predates the field.
	BrokerBuild string

	// SocketStates maps each socket unit to what `systemctl is-active` said
	// before the broker was asked anything. The caller samples it because
	// opening the broker socket activates the service, which Requires= the keeper
	// and executor sockets, so a socket that was down comes up. Empty when the
	// caller did not sample, and then the state is read here.
	SocketStates map[string]string
}

// SampleSockets is each socket unit's state now. Called before anything opens
// the broker socket; see [DoctorOptions.SocketStates].
func SampleSockets() map[string]string {
	if !systemdRunning() {
		return nil
	}
	run := &runner{}
	states := make(map[string]string, len(sockets))
	for _, socket := range sockets {
		out, err := run.command("systemctl", "is-active", socket)
		state := strings.TrimSpace(out)
		// systemctl prints the state even when it exits non-zero, so an empty
		// answer is systemctl itself having failed, as is an error alongside
		// "active".
		if state == "" || (err != nil && state == unitActive) {
			state = "unreportable"
		}
		states[socket] = state
	}
	return states
}

// Status is a finding's verdict.
//
// Warn means the question could not be put, for want of root, runuser, systemd
// or a broker holding values; the install may be perfect. A check that can
// reach its subject and cannot establish it fails instead of guessing.
//
// N/a means the subject belongs to an arrangement this host was not installed
// with. It is reported rather than left out, and is not counted in NotAsked:
// re-running as root would not answer it.
type Status string

const (
	StatusOK     Status = "ok"
	StatusNA     Status = "n/a"
	StatusWarn   Status = "warn"
	StatusFailed Status = "failed"
)

// brokerServes is what the --check probe established about the value set. A
// probe that did not run stays distinct from one that ran and found nothing:
// --check needs root, so conflating them would report every broker examined
// without sudo as one holding no values.
type brokerServes int

const (
	servesUnknown brokerServes = iota
	servesNothing
	servesValues
)

// refusedCode is the error code the broker returns for an op it will not serve
// while a managed file went unread.
const refusedCode = "no_secrets"

// sshAgentRefused is reported both before the probe runs and after the broker
// refuses it.
const sshAgentRefused = "not asked: a managed file did not load, so the broker " +
	"refuses the brokered command this probe runs"

// sshAgentUnanswered is the other reason the probe cannot be put: a broker that
// answered nothing when the install was looked up answers a brokered command no
// better.
const sshAgentUnanswered = "not asked: the broker did not answer, so the " +
	"brokered command this probe runs cannot be sent"

// Finding is one check.
type Finding struct {
	Name   string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// DoctorReport is the whole examination; Failed is the exit code a caller reads.
//
// NotAsked counts the checks that could not be put. A caller has to report it
// alongside the findings: one warn line can stand for a dozen unasked
// questions.
type DoctorReport struct {
	Failed   bool      `json:"failed"`
	NotAsked int       `json:"not_asked"`
	Findings []Finding `json:"findings"`
}

func (d *DoctorReport) addf(name string, status Status, format string, args ...any) {
	d.Findings = append(d.Findings, Finding{
		Name: name, Status: status, Detail: fmt.Sprintf(format, args...),
	})
	if status == StatusFailed {
		d.Failed = true
	}
}

// unaskedf records a check that could not be put: the warn line a reader sees
// and the count under the totals, which have to move together. count is what
// the one line stands for, more than one wherever a bail-out skips a list. A
// warn added through addf is the other kind, something this host has that
// re-running as root would not change.
func (d *DoctorReport) unaskedf(name string, count int, format string, args ...any) {
	d.NotAsked += count
	d.addf(name, StatusWarn, format, args...)
}

// merge appends another report's findings, carrying its verdict and its unasked
// count with them.
func (d *DoctorReport) merge(other DoctorReport) {
	d.Findings = append(d.Findings, other.Findings...)
	d.Failed = d.Failed || other.Failed
	d.NotAsked += other.NotAsked
}

// Diagnose reports whether an install is doing its job, which the install steps
// cannot answer: everything can be written correctly and still protect
// nothing.
func Diagnose(opts DoctorOptions) DoctorReport {
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}
	var report DoctorReport
	configFile := filepath.Join(opts.ConfigDir, "config.toml")

	if !exists(configFile) {
		report.addf(labelConfig, StatusFailed, "%s is missing; the daemons read it at "+
			"startup and exit without one", configFile)
		return report
	}
	report.addf(labelConfig, StatusOK, "%s", configFile)

	// The daemons' own paths rather than the defaults, or a host whose store and
	// sockets moved is examined at addresses nothing uses.
	cfg, err := config.Load(configFile)
	if err != nil {
		report.addf(labelConfig, StatusFailed, "%s does not load: %v", configFile, err)
		return report
	}
	// A test that set the patterns keeps them, having no config to take them
	// from.
	if len(opts.SecretsPatterns) == 0 {
		opts.SecretsPatterns = cfg.Secret.Patterns
	}

	// Before every other check, which each name an account: a wrong name here
	// would be repeated as a confident answer by all of them.
	opts, ok := resolveIdentities(&report, opts, cfg)
	if !ok {
		return report
	}

	// The broker probe first, whatever order it is reported in: the ssh agent and
	// boundaries checks both need to know whether the broker serves anything. Its
	// findings are buffered so they still land in name order below.
	var brokerReport DoctorReport
	serves := diagnoseBroker(&brokerReport, configFile, opts.BrokerUser)

	// What any account can answer, in name order. The ssh agent probe runs a
	// brokered command as the caller's own account.
	diagnoseGroup(&report, opts)
	diagnoseLogRotation(&report, cfg)
	diagnoseUnits(&report, opts)
	diagnoseMemoryBounds(&report)
	diagnoseSSHAgent(&report, opts, cfg, serves)
	diagnoseVersion(&report, opts)

	// Then the checks that need root, grouped so a run without it reads as one
	// block of warnings at the end rather than as gaps between the answers above.
	diagnoseBoundaries(&report, opts, cfg, serves)
	diagnoseKnownHosts(&report, opts, cfg)
	report.merge(brokerReport)
	diagnoseSopsConfig(&report, opts)
	diagnoseAgentRules(&report, opts)
	diagnoseAgentRuleDrift(&report, opts)
	diagnoseLinkedFiles(&report, opts, cfg)
	diagnoseInstallRules(&report, opts)
	diagnoseBlockedPaths(&report, opts, cfg)
	diagnoseLinkedAccess(&report, opts, cfg)
	diagnoseTreeConfig(&report, opts)
	diagnoseEditableFiles(&report, opts)
	return report
}

// diagnoseAgentRules reports every agent and what is configured for it. The
// rules are what refuse the agent's file tools the operator's own key material
// -- ~/.ssh, ~/.config/sops and the like -- which no uid boundary reaches
// because the agent runs as the operator. `faramir init --agent` writes them;
// enrolling a tree does not.
//
// One row each, in use or not: which agents an operator runs cannot be inferred
// from a directory. Only rules missing from an agent in use is a fault.
func diagnoseAgentRules(report *DoctorReport, opts DoctorOptions) {
	if opts.AgentUser == "" {
		report.unaskedf("agent rules", 1, "the agent account is not named, so what "+
			"each agent has in its home was not asked: pass --agent-user, or run "+
			"through sudo so SUDO_USER carries it")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent rules", 1, "could not read %s's home, so what each "+
			"agent has there was not asked", opts.AgentUser)
		return
	}
	enrolled, stale := enrolledAgents(opts.ConfigDir)
	reportAgentRules(report, home, enrolled)
	// A tree that has moved or been deleted since it was enrolled. Reported
	// rather than removed: an unmounted tree is not a deleted one.
	for _, tree := range stale {
		report.addf("agent rules", StatusWarn, "%s was enrolled for %s and is no "+
			"longer there, so that entry says nothing about this host. Re-run "+
			"`faramir init-project` where the tree is now, or ignore it",
			tree.Dir, strings.Join(tree.Agents, ", "))
	}
}

// reportAgentRules is diagnoseAgentRules against a home already resolved, every
// question being about files under a directory rather than about the passwd
// database. enrolled names the agents some tree was enrolled for, which the
// home cannot show: an enrolled agent may leave no trace in this account.
func reportAgentRules(report *DoctorReport, home string, enrolled []string) {
	for _, name := range knownAgents() {
		target := agentTargets[name]
		// An agent with no account-wide file to write, so there is nothing here to
		// find and nothing missing. The target says why.
		if len(target.accountFiles) == 0 {
			report.addf("agent rules", StatusNA, "%s: %s", name, target.withoutAccountRules)
			continue
		}
		var missing []string
		for _, file := range target.accountFiles {
			if !exists(filepath.Join(home, file.path)) {
				missing = append(missing, "~/"+file.path)
			}
		}
		switch {
		case len(missing) == 0:
			report.addf("agent rules", StatusOK, "%s: %s", name,
				strings.Join(accountPaths(target), ", "))
		case slices.Contains(enrolled, name):
			report.addf("agent rules", StatusFailed, "a tree is enrolled for %s and %s "+
				"is not there, so its file tools are refused nothing in that tree. Those "+
				"rules cover the keys under ~/.ssh and ~/.config/sops, which this uid "+
				"can read. Run `sudo faramir init --agent %s`",
				name, strings.Join(missing, ", "), name)
		case agentInUse(home, target):
			report.addf("agent rules", StatusFailed, "%s is in this home and %s is "+
				"not, so its file tools are refused nothing. Those rules cover the keys "+
				"under ~/.ssh and ~/.config/sops, which this uid can read. Run `sudo "+
				"faramir init --agent %s`", name, strings.Join(missing, ", "), name)
		default:
			report.addf("agent rules", StatusNA, "%s: nothing here, so nobody runs it "+
				"from this account", name)
		}
	}
}

// agentInUse reports whether this agent is present in the home at all: its own
// directory, or any of the rules faramir writes for it. The home markers
// rather than the tree ones, so this agrees with `init --agent auto`.
func agentInUse(home string, target *agentTarget) bool {
	for _, marker := range target.detectHome {
		if exists(filepath.Join(home, marker)) {
			return true
		}
	}
	for _, file := range target.accountFiles {
		if exists(filepath.Join(home, file.path)) {
			return true
		}
	}
	return false
}

// accountPaths is an agent's account-wide files, for a finding that names them.
func accountPaths(target *agentTarget) []string {
	out := make([]string, 0, len(target.accountFiles))
	for _, file := range target.accountFiles {
		out = append(out, "~/"+file.path)
	}
	return out
}

// diagnoseSopsConfig reports a creation rule left inside the secrets directory.
// sops takes the first .sops.yaml it finds walking up from the working
// directory, so a copy there shadows the one above it and new values encrypt to
// different recipients depending on where sops was run from. Reported rather
// than moved: guessing which is current wrongly writes values nothing can
// decrypt.
func diagnoseSopsConfig(report *DoctorReport, opts DoctorOptions) {
	layout := Layout{ConfigDir: opts.ConfigDir}
	current, stale := layout.SopsConfigPath(), layout.StaleSopsConfigPath()
	switch {
	case exists(stale) && exists(current):
		report.addf("sops config", StatusWarn, "%s shadows %s for anything run from "+
			"the secrets directory, sops taking the nearest one walking up. Compare the recipients, "+
			"then: sudo rm %s", stale, current, stale)
	case exists(stale):
		report.addf("sops config", StatusWarn, "%s is where earlier installs put it, "+
			"and the secrets directory is globbed by the managed store. Move it: sudo mv %s %s",
			stale, stale, current)
	case exists(current):
		diagnoseSopsRecipients(report, opts, current)
		diagnoseSopsRuleCoverage(report, opts, current)
		diagnoseRecipientDrift(report, opts, current)
	default:
		report.addf("sops config", StatusWarn, "no %s, so sops has no creation rule "+
			"and refuses to encrypt a new file in the secrets directory", current)
	}
}

// diagnoseSopsRecipients answers who can decrypt what the secrets directory
// will hold next. The keeper's own recipient has to be there: without it the
// broker cannot read the next value and still starts and reports healthy. init
// writes this file once, so a key restored or re-minted leaves the rule naming
// the recipient it used to have.
func diagnoseSopsRecipients(report *DoctorReport, opts DoctorOptions, path string) {
	listed, err := sopsRecipients(path)
	if err != nil {
		report.addf("sops config", StatusFailed, "%s does not parse (%v), so who can "+
			"decrypt the secrets directory is unknown here. sops has to read this file too", path, err)
		return
	}
	if len(listed) == 0 {
		report.addf("sops config", StatusWarn, "%s lists no age recipient, so sops "+
			"encrypts a new file in the secrets directory to nobody and refuses", path)
		return
	}
	// The file is 0644, so root can edit it directly, and nothing on that path
	// looks at what was typed: `faramir reader add` validates a key and a hand
	// edit does not. A private half pasted here is the key to the secrets
	// directory, readable by every account. Asked first, the rest assuming
	// entries that at least parse as recipients.
	if !recipientsAreWellFormed(report, listed, path) {
		return
	}
	// The key is 0400 and the keeper's, so this answers only under sudo, and is
	// reported as unchecked rather than as a pass.
	keyPath := filepath.Join(opts.ConfigDir, "age.key")
	keeper, err := agekey.Recipient(keyPath)
	if err != nil {
		report.unaskedf("sops config", 1, "%s lists %s, and whether %s is among "+
			"them went unchecked: %v. Re-run as root", path, strings.Join(listed, ", "),
			keyPath, err)
		return
	}
	// Warn, not failed: the values already in the secrets directory still decrypt,
	// so this is a host that works today and cannot take a new value tomorrow.
	if !slices.Contains(listed, keeper) {
		report.addf("sops config", StatusWarn, "%s lists %s, none of which is the "+
			"recipient of %s (%s). Every value encrypted into the secrets directory "+
			"from now on is one %s cannot decrypt, and a broker that loads nothing "+
			"still starts. Put it back with `sudo faramir reader add %s`, which "+
			"writes the rule and re-seals the store to it",
			path, strings.Join(listed, ", "), keyPath, keeper, opts.KeeperUser, keeper)
		return
	}
	report.addf("sops config", StatusOK, "%s, %d recipient(s) including %s's",
		path, len(listed), opts.KeeperUser)
}

// recipientsAreWellFormed reports every entry sops would refuse, and whether
// there were none. Failed rather than warned: sops encrypts nothing into this
// directory while one is there.
func recipientsAreWellFormed(report *DoctorReport, listed []string, path string) bool {
	ok := true
	for _, recipient := range listed {
		err := agekey.ValidateRecipient(recipient)
		if err == nil {
			continue
		}
		ok = false
		// The error names what to do, including the rotation a private half needs,
		// so it is carried rather than summarised.
		report.addf("sops config", StatusFailed, "%s lists something sops will not "+
			"take as a recipient: %v", path, err)
	}
	return ok
}

// diagnoseSopsRuleCoverage asks whether the creation rules reach every managed
// file, which decides whether `faramir vault edit` and `faramir reader
// reseal` can write one back: sops refuses a file no rule covers.
//
// Each file is put to sops as an encryption of a throwaway document under its
// own name, rather than matching path_regex here: a second implementation of
// that match is free to disagree with sops.
func diagnoseSopsRuleCoverage(report *DoctorReport, opts DoctorOptions, rulePath string) {
	if len(opts.SecretsPatterns) == 0 {
		report.unaskedf("rule coverage", 1, "the managed store could not be read, so "+
			"which files %s has to cover is unknown here", rulePath)
		return
	}
	// filepath.Glob reports a directory it cannot list as no matches and no
	// error, so a caller who cannot read one pattern's directory would get a
	// confident answer about half a store. What did resolve is still checked.
	unlistable := unlistableDirs(opts.SecretsPatterns)
	if len(unlistable) > 0 {
		report.unaskedf("rule coverage", 1, "the directories the managed store "+
			"names cannot be listed by this account (%s), so any managed file under "+
			"them went unchecked. Re-run as root",
			strings.Join(unlistable, ", "))
	}
	managed, _, _ := keeper.Resolve(opts.SecretsPatterns)
	if len(managed) == 0 {
		if len(unlistable) > 0 {
			// Nothing resolved and a directory was unreadable, so the count above
			// stands on its own: reporting nothing to cover would read as an empty
			// store.
			return
		}
		report.addf("rule coverage", StatusNA, "no managed file matches [secret] "+
			"patterns yet, so there is nothing for %s to cover", rulePath)
		return
	}
	sops, err := exec.LookPath("sops")
	if err != nil {
		report.unaskedf("rule coverage", 1, "sops is not on this PATH, and it is what "+
			"decides which rule governs a file: %v", err)
		return
	}
	// The rule's own recipients, named on the command line, so what is asked is
	// whether a rule matches rather than whether its keys work.
	recipients, err := sopsRecipients(rulePath)
	if err != nil {
		report.unaskedf("rule coverage", 1, "%s could not be read, so which files it "+
			"covers went unchecked: %v", rulePath, err)
		return
	}
	covered := 0
	for _, target := range managed {
		switch matched, err := sopsrule.Covers(sops, rulePath, recipients, target); {
		case err != nil:
			report.unaskedf("rule coverage", 1, "whether %s covers %s went unchecked: %v",
				rulePath, target, err)
		case matched:
			covered++
		default:
			report.addf("rule coverage", StatusFailed, "%s has no creation rule "+
				"matching %s, so `faramir vault edit` and `faramir reader reseal` cannot write it back: "+
				"sops refuses a file no rule covers. Widen path_regex to reach it, or keep "+
				"the store where the rule already looks", rulePath, target)
		}
	}
	// Only where every file was asked about and answered yes: an unreadable
	// directory would otherwise be claimed as covered.
	if covered == len(managed) && len(unlistable) == 0 {
		report.addf("rule coverage", StatusOK, "%s covers all %d managed file(s)",
			rulePath, covered)
	}
}

// diagnoseRecipientDrift asks whether every managed file is sealed to what the
// rule names. A store passes `sops config` and `rule coverage` while its
// ciphertext is sealed to a set the rule no longer names: a reseal that failed
// partway, or a rule changed by hand and never applied. Nothing fails in that
// state until somebody reaches for a value with a key they were told they had.
//
// The recipients sops writes into a file are cleartext, so this needs no key,
// only the ability to read the file.
func diagnoseRecipientDrift(report *DoctorReport, opts DoctorOptions, rulePath string) {
	if len(opts.SecretsPatterns) == 0 {
		report.unaskedf("recipient drift", 1, "the managed store could not be read, "+
			"so which files %s has to agree with is unknown here", rulePath)
		return
	}
	wanted, err := sopsRecipients(rulePath)
	if err != nil {
		report.unaskedf("recipient drift", 1, "%s could not be read, so what the "+
			"store should be sealed to is unknown: %v", rulePath, err)
		return
	}
	managed, _, _ := keeper.Resolve(opts.SecretsPatterns)
	if len(managed) == 0 {
		report.addf("recipient drift", StatusNA, "no managed file matches [secret] "+
			"patterns yet, so nothing can disagree with %s", rulePath)
		return
	}
	drifted, checked, sealedToNothing := 0, 0, 0
	for _, target := range managed {
		was, err := sopsrule.SealedTo(target)
		switch {
		// Not drift: a file sealed to nothing is unencrypted or sealed to something
		// other than age, which `rule coverage` and the broker's --check report.
		case errors.Is(err, sopsrule.ErrNoRecipients):
			sealedToNothing++
			continue
		// Unasked rather than failed: a caller who cannot open the file has learned
		// nothing about whether it agrees.
		case err != nil:
			report.unaskedf("recipient drift", 1, "%s could not be read, so whether "+
				"it agrees with %s went unchecked: %v", target, rulePath, err)
			continue
		}
		checked++
		if sopsrule.Same(was, wanted) {
			continue
		}
		drifted++
		report.addf("recipient drift", StatusFailed, "%s is sealed to %s while %s "+
			"names %s, so a key the rule grants may not open it and one it no longer "+
			"grants may. Run: sudo faramir reader reseal",
			target, strings.Join(was, ", "), rulePath, strings.Join(wanted, ", "))
	}
	// Only where every file sealed to anything was reached and agreed. With none
	// sealed there is nothing to pass.
	if drifted == 0 && checked > 0 && checked+sealedToNothing == len(managed) {
		report.addf("recipient drift", StatusOK, "all %d encrypted file(s) are sealed "+
			"to what %s names", checked, rulePath)
	}
}

// unlistableDirs names the directories behind these patterns that this account
// cannot read, which is the difference between a store with no files in it and
// a store this caller cannot see into.
func unlistableDirs(patterns []string) []string {
	var out []string
	for _, pattern := range patterns {
		dir := filepath.Dir(pattern)
		handle, err := os.Open(dir)
		if err != nil {
			// Only a directory that is there and closed to this account; an absent one
			// is a store not written yet.
			if os.IsPermission(err) && !slices.Contains(out, dir) {
				out = append(out, dir)
			}
			continue
		}
		_, err = handle.Readdirnames(1)
		_ = handle.Close()
		if err != nil && !errors.Is(err, io.EOF) && !slices.Contains(out, dir) {
			out = append(out, dir)
		}
	}
	return out
}

// diagnoseLogRotation asks whether anything bounds the audit log. The record
// cap bounds one record and nothing in faramir bounds the file: rotation is
// logrotate's, which has to be installed, has to name this log, and has to be
// run on it. A record carries a brokered command's output, so an agent that
// prints enough fills the disk, and a full disk is where brokered commands stop
// running at all.
//
// Every question is asked of what is on disk: a rule bounding the path
// config.toml named before it was edited, and a rule no run of logrotate ever
// reads, both look like a working rotation from the install's side. The last
// two read logrotate's state and the log itself, which belong to root and to
// the broker, so a caller without root is told they went unasked rather than
// given the pass a failed stat would otherwise imply.
func diagnoseLogRotation(report *DoctorReport, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	logPath := cfg.Audit.LogPath
	if !exists(logrotateConfig) {
		report.addf("log rotation", StatusFailed, "%s does not exist, so nothing "+
			"bounds %s. Re-run `faramir init`, or bound it some other way",
			logrotateConfig, logPath)
		return
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		report.addf("log rotation", StatusFailed, "%s exists and logrotate does not, "+
			"so it is inert and %s grows without a ceiling. Install logrotate, or "+
			"bound that file some other way", logrotateConfig, logPath)
		return
	}

	// The rule has to name the file the broker appends to. Both are rendered
	// from one layout, so they part only where [audit] log_path moved after init,
	// leaving the rule bounding a path nothing writes.
	named, err := logrotateLogs(logrotateConfig)
	switch {
	case err != nil:
		report.addf("log rotation", StatusFailed, "%s cannot be read (%v), so whether "+
			"anything bounds %s cannot be established", logrotateConfig, err, logPath)
		return
	case len(named) == 0:
		report.addf("log rotation", StatusWarn, "%s names no log file, so it is empty "+
			"or written in a form this check cannot read. Confirm it covers %s with "+
			"`logrotate -d %s`", logrotateConfig, logPath, logrotateConfig)
		return
	case !logrotateCovers(named, logPath):
		report.addf("log rotation", StatusFailed, "%s bounds %s and the broker appends "+
			"to %s, so nothing bounds the log this host writes. Point [audit] "+
			"log_path back at the rotated file, or re-run `faramir init` to rewrite "+
			"the rule", logrotateConfig, strings.Join(named, ", "), logPath)
		return
	}

	// What logrotate has processed, the only evidence that the rule is read rather
	// than merely installed: one the include line does not reach, or that a syntax
	// error earlier in the set abandons, is skipped every run.
	statePath := firstExisting(logrotateStatePaths)
	if statePath == "" {
		report.addf("log rotation", StatusWarn, "logrotate keeps no state at %s, so it "+
			"has not run on this host and %s is bounded by a rule nothing has applied. "+
			"Check the logrotate timer or cron job",
			strings.Join(logrotateStatePaths, " or "), logPath)
		return
	}
	rotated, err := logrotateStateLogs(statePath)
	switch {
	case os.IsPermission(err):
		report.unaskedf("log rotation", 1, "run doctor as root to ask the rest: %s "+
			"says which logs logrotate has processed and %s is the broker's, so "+
			"whether the rule is being applied and how large the log has grown are "+
			"both root's to read. %s does name %s",
			statePath, logPath, logrotateConfig, logPath)
		return
	case err != nil:
		report.addf("log rotation", StatusFailed, "%s cannot be read (%v), so whether "+
			"logrotate has ever applied %s cannot be established",
			statePath, err, logrotateConfig)
		return
	case !slices.Contains(rotated, logPath):
		report.addf("log rotation", StatusWarn, "%s names %d logs and not %s, so "+
			"logrotate has not applied the rule to it. A host whose first run has not "+
			"come round yet is the ordinary reason; past that, %s is not being read. "+
			"Check the logrotate timer or cron job",
			statePath, len(rotated), logPath, logrotateConfig)
		return
	}

	// The rule rotates at 16MB, so a log far past it is one logrotate is not being
	// run on. A multiple rather than the size itself: rotation is scheduled, so a
	// log over it between two runs is ordinary.
	const rotateSize = 16 << 20
	info, err := os.Stat(logPath)
	switch {
	case os.IsPermission(err):
		report.unaskedf("log rotation", 1, "run doctor as root to ask the last of "+
			"this: %s is the broker's, so its size is root's to read. %s does name "+
			"it, and %s records that logrotate has applied the rule",
			logPath, logrotateConfig, statePath)
		return
	// Absent is not a fault: the rule is missingok and the broker opens the file
	// with O_CREATE, so the next record makes it again.
	case err == nil && info.Size() > 4*rotateSize:
		report.addf("log rotation", StatusWarn, "%s is %d bytes, well past the %d "+
			"the rule rotates at, so logrotate is installed and is not being run on "+
			"it. Check the logrotate timer or cron job",
			logPath, info.Size(), rotateSize)
		return
	}
	report.addf("log rotation", StatusOK, "%s bounds %s, logrotate is installed to "+
		"apply it, and %s records that it has", logrotateConfig, logPath, statePath)
}

// logrotateLogs is the log files a rule file names: every path outside a
// directive block, which is where logrotate takes its file list from. A parser
// rather than `logrotate -d`, whose output is prose that differs between
// versions. Blocks are skipped by brace depth, so a postrotate script carrying
// braces of its own can hide a path from this; the caller reports finding none
// as a rule it could not read.
func logrotateLogs(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var logs []string
	depth := 0
	for line := range strings.SplitSeq(string(body), "\n") {
		if comment := strings.IndexByte(line, '#'); comment >= 0 {
			line = line[:comment]
		}
		for field := range strings.FieldsSeq(line) {
			// logrotate lexes the brace as its own token, so a path can carry one
			// with no space between them.
			if trimmed, ok := strings.CutSuffix(field, "{"); ok {
				if depth == 0 && trimmed != "" {
					logs = append(logs, unquoteField(trimmed))
				}
				depth++
				continue
			}
			switch {
			case field == "}":
				depth = max(depth-1, 0)
			case depth > 0:
				// A directive rather than a path.
			default:
				logs = append(logs, unquoteField(field))
			}
		}
	}
	return logs, nil
}

// logrotateCovers reports whether a rule naming these logs covers the one the
// broker writes. Globs count: a rule may name /var/log/faramir/*.log, which
// bounds audit.log without spelling it.
func logrotateCovers(named []string, logPath string) bool {
	for _, candidate := range named {
		if candidate == logPath {
			return true
		}
		if matched, err := filepath.Match(candidate, logPath); err == nil && matched {
			return true
		}
	}
	return false
}

// logrotateStateLogs is every log logrotate's state file names, which is every
// log it has processed. One line per log, the path first and quoted since
// version 2, then the date it was last rotated, which is not read here: under
// notifempty a quiet log is never rotated, so the date says how busy the host
// has been rather than whether the rule is applied.
func logrotateStateLogs(path string) ([]string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var logs []string
	for line := range strings.SplitSeq(string(body), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "logrotate state") {
			continue
		}
		if strings.HasPrefix(line, `"`) {
			// A quoted path may hold spaces, so it ends at its own quote rather
			// than at the first field boundary.
			if end := strings.IndexByte(line[1:], '"'); end >= 0 {
				logs = append(logs, line[1:end+1])
				continue
			}
		}
		logs = append(logs, strings.Fields(line)[0])
	}
	return logs, nil
}

// firstExisting is the first of these paths this host has, or "" for none.
func firstExisting(paths []string) string {
	for _, path := range paths {
		if exists(path) {
			return path
		}
	}
	return ""
}

// unquoteField drops one matching pair of quotes.
func unquoteField(field string) string {
	for _, quote := range []string{`"`, `'`} {
		if len(field) > 1 && strings.HasPrefix(field, quote) && strings.HasSuffix(field, quote) {
			return field[1 : len(field)-1]
		}
	}
	return field
}

// diagnoseUnits reports the sockets, not the services: all three are socket
// activated, so an inactive service is ordinary.
func diagnoseUnits(report *DoctorReport, opts DoctorOptions) {
	if !systemdRunning() {
		report.unaskedf("sockets", len(sockets), "systemd is not running here, so whether "+
			"%d socket unit(s) are listening was not asked", len(sockets))
		return
	}
	// What the caller saw before it opened the broker socket. Reading the state
	// here would read it after that round trip, which starts any socket the broker
	// depends on, so all three would report as listening.
	states := opts.SocketStates
	if len(states) == 0 {
		states = SampleSockets()
	}
	for _, socket := range sockets {
		state, sampled := states[socket]
		if !sampled {
			state = "unreportable"
		}
		if state != unitActive {
			report.addf("sockets", StatusFailed, "%s is %s; check journalctl -u %s",
				socket, state, socket)
			continue
		}
		report.addf("sockets", StatusOK, "%s is listening", socket)
	}
}

// gib renders a byte count the way an operator sizes one of these: the config
// key is in MB and the unit resolves to bytes, and neither reads at a glance.
func gib(bytes int64) string {
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
}

// diagnoseMemoryBounds reads what the executor unit's two memory limits resolve
// to and reports when the per-process one is out of reach.
//
// They answer different questions and are sized against different things, so
// nothing stops an operator setting a per-process bound above the cgroup total.
// Where that happens the cgroup is met first and the OOM killer picks a victim,
// which is the outcome the per-process bound was chosen over: it hands the
// process an allocation failure it can report instead. The defaults cross on a
// host with less memory than four times the percentage, so a laptop reaches
// this without anybody configuring anything.
//
// Read from systemd rather than computed from the config: the percentage
// resolves against the cgroup's own limit, which inside a container is the
// container's and not the machine's, and only systemd knows which.
func diagnoseMemoryBounds(report *DoctorReport) {
	const check = "memory bounds"
	if !systemdRunning() {
		report.unaskedf(check, 1, "systemd is not running here, so what the "+
			"executor's memory limits resolve to was not asked")
		return
	}
	run := &runner{}
	limit := func(property string) (int64, bool) {
		out, err := run.command("systemctl", "show", execUnit, "-p", property, "--value")
		if err != nil {
			return 0, false
		}
		value, convErr := strconv.ParseInt(strings.TrimSpace(out), 10, 64)
		// "infinity" is systemd saying there is no limit, which parses as neither
		// a number nor an error worth reporting: it is a bound nobody set.
		return value, convErr == nil
	}
	maxMemory, haveMax := limit("MemoryMax")
	perProcess, havePer := limit("LimitDATA")
	reportMemoryBounds(report, perProcess, havePer, maxMemory, haveMax)
}

// reportMemoryBounds is the verdict on two resolved limits, apart from reading
// them so the judgement can be asserted without systemd.
func reportMemoryBounds(report *DoctorReport, perProcess int64, havePer bool,
	maxMemory int64, haveMax bool) {
	const check = "memory bounds"
	switch {
	case !haveMax && !havePer:
		report.addf(check, StatusWarn, "%s bounds neither the executor's memory "+
			"nor one process's, so a brokered command that runs away is bounded by "+
			"the machine. `sudo faramir init` writes both", execUnit)
	case !havePer:
		report.addf(check, StatusWarn, "%s bounds the executor at %s and one "+
			"process not at all, so a runaway is stopped by the OOM killer rather "+
			"than by an allocation failure it can report", execUnit, gib(maxMemory))
	case !haveMax:
		report.addf(check, StatusOK, "one brokered process may allocate %s, and "+
			"the executor as a whole is unbounded", gib(perProcess))
	case perProcess >= maxMemory:
		report.addf(check, StatusWarn, "one process may allocate %s while the "+
			"executor as a whole is held to %s, so the per-process bound is out of "+
			"reach: a runaway meets the OOM killer rather than the allocation "+
			"failure it exists to hand back. Lower [command] max_process_memory_mb "+
			"below %s, then `sudo faramir init`",
			gib(perProcess), gib(maxMemory), gib(maxMemory))
	default:
		report.addf(check, StatusOK, "one brokered process may allocate %s, and "+
			"every brokered command together %s",
			gib(perProcess), gib(maxMemory))
	}
}

// diagnoseVersion compares the running broker against the binary asking. They
// diverge when a new binary was installed and the daemons were not restarted
// onto it, which leaves every other finding describing the wrong build: the
// checks read this build's paths, modes and config rules. A fail rather than a
// warn: an upgrade did not finish, and re-running init is what finishes it.
func diagnoseVersion(report *DoctorReport, opts DoctorOptions) {
	switch {
	case opts.BrokerVersion == "":
		// A broker that is running answers this even when it refuses the
		// request for naming another version, every error naming the build
		// that answered, so nothing here is a broker that is not up.
		report.unaskedf("version", 1, "the broker did not answer, so which build "+
			"is running is unknown; this binary is %s", version.Version)
	case opts.BrokerVersion != version.Version:
		report.addf("version", StatusFailed, "the broker is running %s and this binary "+
			"is %s, so the daemons were never restarted onto what is installed and "+
			"every finding below describes the wrong build. Run `sudo faramir init`",
			opts.BrokerVersion, version.Version)
	// Same version, different build. Every unstamped binary reports "dev", so
	// the comparison above passes between two of them and this is what catches
	// a daemon left on the binary it was started from. Both sides have to name
	// a build for the difference to mean anything: a release names none, and
	// neither does a broker older than the field.
	case version.Build != "" && opts.BrokerBuild != "" &&
		opts.BrokerBuild != version.Build:
		report.addf("version", StatusFailed, "the broker and this binary are both %s "+
			"but they are different builds, %s against %s, so the daemons were never "+
			"restarted onto what is installed and every finding below describes the "+
			"wrong build. Run `sudo faramir init`",
			version.Version, opts.BrokerBuild, version.Build)
	case version.Build != "":
		report.addf("version", StatusOK, "broker and binary are both %s (%s)",
			version.Version, version.Build)
	default:
		report.addf("version", StatusOK, "broker and binary are both %s", version.Version)
	}
}

// diagnoseBroker asks the broker what it can do. A value absent from the set
// is neither injectable nor redacted, so a broker serving zero refs from a
// secrets directory that exists is protecting nothing and looks healthy.
//
// Run as the broker's own uid, which is why this needs root: --check opens the
// keeper socket, the SSH keys and the secrets files itself.
func diagnoseBroker(report *DoctorReport, configFile, brokerUser string) brokerServes {
	if os.Geteuid() != 0 {
		report.unaskedf("broker", 1, "run doctor as root to ask this: --check "+
			"has to run as %s, and any other account gets an answer that is not "+
			"the broker's", brokerUser)
		return servesUnknown
	}
	run := &runner{}
	// Read the report before the exit code is judged. --check exits non-zero on
	// every state below, so trusting the status alone would report all of them
	// as one unexplained failure.
	out, checkErr := run.command("runuser", "-u", brokerUser, "--",
		"env", "FARAMIR_CONFIG="+configFile,
		filepath.Join(DefaultBinDir, "faramir"), "broker", "--check")
	var check checkReport
	if err := json.Unmarshal([]byte(out), &check); err != nil {
		if checkErr != nil {
			report.addf("broker", StatusFailed, "--check failed as %s: %v", brokerUser, checkErr)
			return servesUnknown
		}
		report.addf("broker", StatusFailed, "could not read the --check report: %v", err)
		return servesUnknown
	}
	const store = "secrets store"
	status, detail := storeFinding(check)
	report.addf(store, status, "%s", detail)
	// Whether this accounted for a non-zero --check. Only a clean store leaves it
	// unexplained; a warning is still this function having named the reason.
	explained := status != StatusOK

	// Refs the store read and the redactor refused. Named here rather than left
	// to the fallback below, which would report a condition --check describes
	// precisely as one it cannot explain. A failure: a ref the config names does
	// not answer, which is the same degraded host `faramir status` exits non-zero
	// over, and doctor saying warn where status says fail would leave the two
	// describing different hosts.
	if len(check.Secrets.NotRedactable) > 0 {
		report.addf("refused refs", StatusFailed, "%d ref(s) cannot be redacted, so "+
			"they are never injected and never redacted: %s. Fix each with `sudo "+
			"faramir vault edit`; the reason beside it says how",
			len(check.Secrets.NotRedactable), check.refusedRefs())
		if check.onlyNotRedactable() {
			explained = true
		}
	}
	// A ref two managed files both defined. Reported beside the refused refs because
	// the consequence is the same one: a value this host manages that is injected
	// by nothing and covered by nothing, so a command printing it prints it. The
	// difference is that a short value is knowingly outside the redactor and this
	// one is not, which is why it is named rather than left to a daemon log line.
	if len(check.Secrets.ShadowedRefs) > 0 {
		report.addf("shadowed refs", StatusFailed, "%d ref(s) are defined with "+
			"different values by more than one managed file. One value wins and the "+
			"other is injected by nothing and redacted by nothing, so a command that "+
			"prints it prints it in the clear: %s. Take the ref out of one of the "+
			"files with `sudo faramir vault edit`",
			len(check.Secrets.ShadowedRefs), refsWithReasons(check.Secrets.ShadowedRefs))
		if check.onlyShadowedRefs() {
			explained = true
		}
	}
	// Links that did not load, read out of the file rather than off its mode:
	// this catches a selector the owning tool stopped writing, which no mode says
	// anything about, and which diagnoseLinkedAccess therefore cannot see.
	//
	// What a fresh load of this config produces, not what the running daemon
	// holds. The two differ after a linked file is repaired by hand: the broker
	// fingerprints one by mtime and size, and a `chgrp` changes neither, so its
	// view stands until it is restarted. Nothing does that on its own, which is
	// why the remedy says so.
	//
	// A failure: the ref answers nothing, and nothing else surfaces that until a
	// command asks for it.
	if len(check.Secrets.DegradedLinks) > 0 {
		report.addf("linked refs", StatusFailed, "%s did not load, so those refs "+
			"answer nothing while every other ref is served: %s. Fix what each one "+
			"needs, then `sudo systemctl restart faramir-broker`: the broker "+
			"fingerprints a linked file by mtime and size, so a repair that changes "+
			"neither leaves its view as it was",
			linkEntries(len(check.Secrets.DegradedLinks)), check.degradedRefs())
		if check.onlyDegradedLinks() {
			explained = true
		}
	}
	// --check fails for reasons the switch does not cover: an unusable [ssh] key,
	// a bound socket with world bits. Judged on whether this function accounted
	// for the exit code rather than on whether anything else in the report
	// failed.
	if checkErr != nil && !explained {
		report.addf("broker", StatusFailed, "--check failed as %s for a reason not "+
			"reported above: %v", brokerUser, checkErr)
	}
	// A probe that ran a brokered command against a refusing broker would report
	// the refusal as whatever it was probing for.
	if check.serves() {
		return servesValues
	}
	return servesNothing
}

// diagnoseSSHAgent asks what a brokered command would actually get, rather than
// reading the key off disk, and asks as the operator: root is not in the client
// group the broker checks against.
//
// Skipped when no key is configured: SSH is then arranged for the executor's
// uid some other way, and `ssh-add -l` exits non-zero for want of an agent,
// which is not a fault. Not skipped for want of root.
func diagnoseSSHAgent(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	if cfg == nil {
		report.unaskedf("ssh agent", 1, "the config did not load, so which key the "+
			"broker lends is unknown")
		return
	}
	// An install always writes one: `init` mints a key whether or not the host
	// turns out to need it, and renders the path into [ssh] key, so an empty one
	// is an edit rather than a host that authenticates some other way. Reported
	// as a fault because nothing else would say so: the broker comes up, every
	// other check passes, and a brokered command reaching a managed host fails
	// with ssh's own error at the point of use.
	if cfg.Ssh.Key == "" {
		where := cfg.Path
		if where == "" {
			where = "the config"
		}
		report.addf("ssh agent", StatusFailed, "no [ssh] key is configured, so the "+
			"broker lends no identity and a brokered command that reaches a managed "+
			"host fails at the point of use, with ssh's own error. `faramir init` "+
			"writes one on every run, so this is an edit to %s. Re-run `sudo faramir "+
			"init`, with --ssh-key to name one of your own", where)
		return
	}
	if reason := skipSSHProbe(serves, opts.BrokerVersion); reason != "" {
		report.unaskedf("ssh agent", 1, "%s", reason)
		return
	}
	out, err := asOperator(opts, filepath.Join(DefaultBinDir, "faramir"),
		"run", "--quiet", "--", "ssh-add", "-l")
	reportSSHProbe(report, cfg, serves, out, err)
}

// skipSSHProbe reports why the probe cannot be put, empty when it can. The
// probe sends a brokered command, so a broker that refuses one or answers
// nothing leaves no answer to be had, and reporting either as the agent's own
// would fail a host whose agent is fine. The established refusal comes first:
// it names the fault to fix.
func skipSSHProbe(serves brokerServes, brokerVersion string) string {
	switch {
	case serves == servesNothing:
		return sshAgentRefused
	case brokerVersion == "":
		return sshAgentUnanswered
	}
	return ""
}

// reportSSHProbe turns the probe's answer into a finding. A refusal from a
// broker --check found holding values is neither the agent's answer nor a skip:
// --check reads the managed files itself, so a daemon refusing what those files
// cover came up before they were written.
func reportSSHProbe(report *DoctorReport, cfg *config.Config, serves brokerServes, out string, err error) {
	switch classifySSHProbe(out, err) {
	case sshProbeHasKey:
		report.addf("ssh agent", StatusOK, "holds a usable key")
	case sshProbeRefused:
		if serves == servesValues {
			report.addf("ssh agent", StatusFailed, "the broker refuses brokered commands "+
				"though --check read every managed file as the broker: the running daemon "+
				"came up before the values were there and has not read them since. "+
				"Restart faramir-broker")
			return
		}
		report.unaskedf("ssh agent", 1, "%s", sshAgentRefused)
	case sshProbeEmpty:
		report.addf("ssh agent", StatusFailed, "the agent holds nothing, though [ssh] "+
			"key names %s, so every brokered command that reaches a managed host "+
			"fails to authenticate. Place the key and restart faramir-broker",
			cfg.Ssh.Key)
	case sshProbeUnreachable:
		report.addf("ssh agent", StatusFailed, "could not ask the broker: %v: %s",
			err, strings.TrimSpace(out))
	}
}

// sshProbeResult is what `ssh-add -l` through the broker came back as.
type sshProbeResult int

const (
	sshProbeHasKey sshProbeResult = iota
	sshProbeRefused
	sshProbeEmpty
	sshProbeUnreachable
)

// classifySSHProbe reads the probe's answer. Success first: ssh-add exits
// non-zero both when the agent is empty and when it could not be reached, so
// err alone does not say which and the output decides. The refusal is the
// broker declining to run the probe at all.
func classifySSHProbe(out string, err error) sshProbeResult {
	switch {
	case strings.Contains(out, "SHA256"):
		return sshProbeHasKey
	case err != nil && strings.Contains(err.Error(), refusedCode):
		return sshProbeRefused
	case strings.Contains(out, "no identities"):
		return sshProbeEmpty
	}
	return sshProbeUnreachable
}

// diagnoseGroup lists members of the two granting groups that this install does
// not account for. Reported rather than removed: whose grant that is, is not
// this command's to decide.
//
// Both groups, because both survive a re-run that renames what they are for:
// changing --client-group leaves the old group intact with every member, and a
// new --keeper-user leaves the retired account in the group owning the
// ciphertext.
func diagnoseGroup(report *DoctorReport, opts DoctorOptions) {
	// A list so the bail-out below can say how many went unasked.
	type granting struct{ label, name, grants string }
	groups := []granting{
		{"client group", opts.ClientGroup,
			"reach the broker socket, and enter a tree enrolled with it"},
	}
	// Only where the secrets group is not the client group, which is already
	// listed.
	if opts.SecretsGroup != "" && opts.SecretsGroup != opts.ClientGroup {
		groups = append(groups, granting{"secrets group", opts.SecretsGroup,
			"read and replace the ciphertext in the secrets directory"})
	}
	// The operator is a member of the client group by construction, so without
	// their name the account this install admitted cannot be told from one left
	// behind, and the remedy printed would be the one change that shuts the agent
	// out of the broker socket.
	if opts.AgentUser == "" {
		report.unaskedf("client group", len(groups), "the agent account is not "+
			"named, so a member of %s cannot be told from an account left behind: "+
			"pass --agent-user, or run through sudo so SUDO_USER carries it",
			opts.ClientGroup)
		return
	}
	// The agent's account belongs in the client group and nowhere near the
	// secrets group: membership there is read on the ciphertext, which is the one
	// grant this install exists to keep from it. Calling it expected in both left
	// one line saying "no unexpected members" beside another failing over that
	// exact member.
	service := []string{opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	for _, group := range groups {
		known := service
		if group.name == opts.ClientGroup {
			known = append(append([]string{}, service...), opts.AgentUser)
		}
		diagnoseGroupOutsiders(report, group.label, group.name, known, group.grants)
	}
}

// diagnoseGroupOutsiders is one group's membership against the accounts this
// install uses. Primary membership as well as supplementary: /etc/group lists
// only the second, and a renamed --keeper-user leaves an account holding the
// secrets group as its primary, which is the case worth reporting.
func diagnoseGroupOutsiders(report *DoctorReport, label, name string, known []string, grants string) {
	gid, members, err := groupEntry(name)
	if err != nil {
		report.addf(label, StatusFailed, "no group %q, so nothing can %s", name, grants)
		return
	}
	primary, err := primaryMembers(gid)
	if err != nil {
		report.addf(label, StatusFailed, "could not read who holds %s as a primary "+
			"group (%v), so who can %s went unverified", name, err, grants)
		return
	}
	var outsiders []string
	for _, member := range append(members, primary...) {
		if member != "" && !slices.Contains(known, member) &&
			!slices.Contains(outsiders, member) {
			outsiders = append(outsiders, member)
		}
	}
	if len(outsiders) == 0 {
		report.addf(label, StatusOK, "%s has no unexpected members", name)
		return
	}
	report.addf(label, StatusWarn, "%s has members this install does not use: %s. "+
		"Membership is what lets them %s, so an account the install has stopped "+
		"naming is a standing grant. Drop one with: gpasswd -d <account> %s, or "+
		"usermod -g <other> <account> where it is the primary group",
		name, strings.Join(outsiders, ", "), grants, name)
}

// passwdFile is where the accounts are. A variable so a test can point at one
// it wrote.
var passwdFile = "/etc/passwd"

// primaryMembers is the accounts whose primary gid is this group, which
// /etc/group does not record.
func primaryMembers(gid string) ([]string, error) {
	body, err := os.ReadFile(passwdFile)
	if err != nil {
		return nil, err
	}
	var accounts []string
	for line := range strings.Lines(string(body)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) >= 4 && fields[3] == gid {
			accounts = append(accounts, fields[0])
		}
	}
	return accounts, nil
}

// groupFile is where the groups are. A variable so a test can point at one it
// wrote.
var groupFile = "/etc/group"

// groupEntry is a group's gid and its supplementary members, read from the same
// line so both describe one entry. The gid is what the primary members are
// found by.
func groupEntry(name string) (gid string, members []string, err error) {
	body, readErr := os.ReadFile(groupFile)
	if readErr != nil {
		return "", nil, readErr
	}
	for line := range strings.Lines(string(body)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		if fields[3] == "" {
			return fields[2], nil, nil
		}
		return fields[2], strings.Split(fields[3], ","), nil
	}
	return "", nil, fmt.Errorf("no group %q in %s", name, groupFile)
}

// resolveIdentities finds the accounts and groups this install actually uses,
// rather than the ones a default would name: every check below asks what a
// named account can reach, so a wrong name answers confidently about an account
// this host may not have.
//
// The unit is the source of truth for a service account, being what systemd
// reads; the config for the client group, being what the broker checks; and the
// secrets directory's own group for the secrets group, being what the modes are
// set to. A flag still wins, for a host whose install is not this machine's.
//
// Failing rather than falling back: each of these is readable on any working
// install.
func resolveIdentities(report *DoctorReport, opts DoctorOptions, cfg *config.Config) (DoctorOptions, bool) {
	for _, role := range []struct {
		unit string
		into *string
		flag string
	}{
		{brokerUnit, &opts.BrokerUser, "--broker-user"},
		{keeperUnit, &opts.KeeperUser, "--keeper-user"},
		{execUnit, &opts.ExecUser, "--exec-user"},
	} {
		if *role.into != "" {
			continue
		}
		account, err := unitUser(role.unit)
		if err != nil {
			report.addf("identities", StatusFailed, "cannot tell which account runs "+
				"%s (%v), so nothing below could be asked about the right one. Reinstall, "+
				"or pass %s", role.unit, err, role.flag)
			return opts, false
		}
		*role.into = account
	}

	if opts.ClientGroup == "" {
		if cfg.Server.AllowedGroup == "" {
			report.addf("identities", StatusFailed, "[server] allowed_group is unset, so "+
				"the broker admits nobody but root and itself. Run `faramir init "+
				"--client-group NAME`, or pass --client-group to examine anyway")
			return opts, false
		}
		opts.ClientGroup = cfg.Server.AllowedGroup
	}
	if opts.SecretsGroup == "" {
		dir := filepath.Join(opts.ConfigDir, "secrets")
		group, err := groupOf(dir)
		if err != nil {
			report.addf("identities", StatusFailed, "cannot read the group owning %s "+
				"(%v), which is what keeps every account but the keeper out of the "+
				"ciphertext. Reinstall, or pass --secrets-group", dir, err)
			return opts, false
		}
		opts.SecretsGroup = group
	}

	report.addf("identities", StatusOK, "%s, %s, %s, in %s, secrets owned by %s",
		opts.BrokerUser, opts.KeeperUser, opts.ExecUser, opts.ClientGroup, opts.SecretsGroup)
	return opts, true
}

// groupOf is the group name owning a path.
func groupOf(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot read ownership", path)
	}
	group, err := user.LookupGroupId(strconv.Itoa(int(stat.Gid)))
	if err != nil {
		return "", err
	}
	return group.Name, nil
}
