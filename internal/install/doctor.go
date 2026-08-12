package install

import (
	"encoding/json"
	"fmt"
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
	"github.com/andornaut/faramir/internal/version"
)

// DoctorOptions is what Diagnose needs to find an install it did not perform.
type DoctorOptions struct {
	ConfigDir    string
	OperatorUser string
	ClientGroup  string
	// The three service accounts, so the group audit recognises the ones this
	// install created rather than reporting them as intruders.
	BrokerUser string
	KeeperUser string
	ExecUser   string
	// SecretsGroup owns the managed sops files, defaulting to the keeper's own
	// group as install leaves it.
	SecretsGroup string

	// BrokerVersion is what the running broker reported, empty when it did not
	// answer.  Passed in rather than asked for here, the caller already having
	// opened the socket to find the install.
	BrokerVersion string

	// SocketStates is each socket unit's state as it was before the broker was
	// asked anything, unit name to what `systemctl is-active` said.  Sampled by
	// the caller because the caller's own round trip changes it: opening the
	// broker socket activates the service, which Requires= the keeper and
	// executor sockets, so a socket that was down comes up and the examination
	// reports the host it made rather than the one it met.
	//
	// Empty when the caller did not sample, and then the state is read here.
	SocketStates map[string]string
}

// SampleSockets is each socket unit's state now.  Called before anything opens
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
		// answer is systemctl itself having failed.  Named, or the finding reads
		// "<socket> is ;".  An error alongside "active" is the same contradiction
		// and is not reported as a unit that is up.
		if state == "" || (err != nil && state == unitActive) {
			state = "unreportable"
		}
		states[socket] = state
	}
	return states
}

// Status is a finding's verdict.  Four levels, because a broker that is
// running and holding nothing is neither a pass nor a fail, and neither is a
// check whose subject this host does not have.
//
// Warn means the question could not be asked, and the reason is how doctor was
// invoked or what this host is: no root, no runuser, no systemd, nothing
// managed to probe with, a socket-activated broker still idle.  The install may
// be perfect.
//
// It does not mean "tried to read something every install has and failed".
// That is a fail: .sops.yaml that will not parse is one sops cannot parse
// either, a client group whose members cannot be listed is an admission nobody
// verified, and a broker that will not answer is a broker not doing its job.
// A confident answer about the wrong thing is worse than no answer, so a check
// that cannot establish its own subject fails rather than guessing.
//
// N/a means the question does not arise here: the subject belongs to an
// arrangement this host was not installed with, so there is nothing to pass or
// fail.  It is reported rather than left out, a check that vanishes being
// indistinguishable from one nobody wrote.  It is not counted in NotAsked:
// re-running as root is not what would answer it, and nothing about this host
// is unexamined.
type Status string

const (
	StatusOK     Status = "ok"
	StatusNA     Status = "n/a"
	StatusWarn   Status = "warn"
	StatusFailed Status = "failed"
)

// brokerServes is what the --check probe established about the value set.  A
// probe that did not run has to stay distinct from one that ran and found
// nothing: --check needs root, so reading the two as the same reports every
// broker examined without sudo as one holding no values, and skips the probes
// that key off it citing a state the broker is not in.
type brokerServes int

const (
	servesUnknown brokerServes = iota
	servesNothing
	servesValues
)

// refusedCode is the error code the broker returns for an op it will not serve
// while a managed file went unread.  A probe that runs a brokered command has
// to tell that refusal from an answer, or it reports the refusal as whatever it
// was probing for.
const refusedCode = "no_secrets"

// sshAgentRefused is stated once, being reported both before the probe runs and
// after the broker refuses it.
const sshAgentRefused = "not asked: the broker holds no managed values, so it " +
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

// DoctorReport is the whole examination; Failed is the exit code a caller
// reads.
//
// NotAsked counts the checks that could not be put, for want of root, of a
// broker holding values or of one running at all.  A caller has to report it
// alongside the findings: one warn line stands for a dozen unasked questions,
// so the totals alone read as a complete examination of a host that was barely
// examined.
type DoctorReport struct {
	Failed   bool      `json:"failed"`
	NotAsked int       `json:"not_asked"`
	Findings []Finding `json:"findings"`
}

func (d *DoctorReport) add(name string, status Status, format string, args ...any) {
	d.Findings = append(d.Findings, Finding{
		Name: name, Status: status, Detail: fmt.Sprintf(format, args...),
	})
	if status == StatusFailed {
		d.Failed = true
	}
}

// unasked is a check that could not be put: the warn line a reader sees and the
// count under the totals, which have to move together.  count is what the one
// line stands for, which is more than one wherever a bail-out skips a list.
//
// The pairing is here rather than at each site because nothing else enforces it.
// A warn added through add() is the other kind: a finding this host has, worth
// reporting and short of a failure -- an open sysctl, a stale rule, a group with
// members nobody recognises -- and re-running as root would not change it.  Which
// kind a warn is, is now which call it goes through.
func (d *DoctorReport) unasked(name string, count int, format string, args ...any) {
	d.NotAsked += count
	d.add(name, StatusWarn, format, args...)
}

// merge appends another report's findings, carrying its verdict and its unasked
// count with them.
func (d *DoctorReport) merge(other DoctorReport) {
	d.Findings = append(d.Findings, other.Findings...)
	d.Failed = d.Failed || other.Failed
	d.NotAsked += other.NotAsked
}

// Diagnose reports whether an install is doing its job: the questions the
// install steps cannot answer, everything having been written correctly and the
// result still protecting nothing.
func Diagnose(opts DoctorOptions) DoctorReport {
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}
	var report DoctorReport
	configFile := filepath.Join(opts.ConfigDir, "config.toml")

	if !exists(configFile) {
		report.add("config", StatusFailed, "%s is missing; the daemons read it at "+
			"startup and exit without one", configFile)
		return report
	}
	report.add("config", StatusOK, "%s", configFile)

	// The daemons' own paths rather than the defaults, or a host whose store and
	// sockets moved is examined at addresses nothing uses.
	cfg, err := config.Load(configFile)
	if err != nil {
		report.add("config", StatusFailed, "%s does not load: %v", configFile, err)
		return report
	}

	// Before every other check, which each name an account: a wrong name here
	// would be repeated as a confident answer by all of them.
	opts, ok := resolveIdentities(&report, opts, cfg)
	if !ok {
		return report
	}

	// The broker probe first, whatever order it is reported in: it is what says
	// whether the broker serves anything, which the ssh agent and boundaries
	// checks both need before they run.  Its own findings are buffered so they
	// still land in name order below.
	var brokerReport DoctorReport
	serves := diagnoseBroker(&brokerReport, configFile, opts.BrokerUser)

	// What any account can answer, in name order.  The ssh agent probe belongs
	// here: it runs a brokered command as the operator, which is the caller's own
	// account whenever doctor was not run as root.
	diagnoseGroup(&report, opts)
	diagnoseLogRotation(&report, cfg)
	diagnoseUnits(&report, opts)
	diagnoseSSHAgent(&report, opts, cfg, serves)
	diagnoseVersion(&report, opts)

	// Then the checks that need root, grouped so a run without it reads as one
	// block of warnings at the end rather than as gaps between the answers above.
	diagnoseBoundaries(&report, opts, cfg, serves)
	diagnoseKnownHosts(&report, opts, cfg)
	report.merge(brokerReport)
	diagnoseSopsConfig(&report, opts)
	return report
}

// diagnoseSopsConfig reports a creation rule left inside the secrets directory.
// sops takes the first .sops.yaml it finds walking up from the working
// directory, so a copy in the secrets directory shadows the one above it and
// new values encrypt to different recipients depending on the working directory
// sops was run from.
//
// Reported rather than moved: answering which is current wrongly writes values
// nothing can decrypt.
func diagnoseSopsConfig(report *DoctorReport, opts DoctorOptions) {
	layout := Layout{ConfigDir: opts.ConfigDir}
	current, stale := layout.SopsConfigPath(), layout.StaleSopsConfigPath()
	switch {
	case exists(stale) && exists(current):
		report.add("sops config", StatusWarn, "%s shadows %s for anything run from "+
			"the secrets directory, sops taking the nearest one walking up. Compare the recipients, "+
			"then: sudo rm %s", stale, current, stale)
	case exists(stale):
		report.add("sops config", StatusWarn, "%s is where earlier installs put it, "+
			"and the secrets directory is globbed by [secrets] patterns. Move it: sudo mv %s %s",
			stale, stale, current)
	case exists(current):
		diagnoseSopsRecipients(report, opts, current)
	default:
		report.add("sops config", StatusWarn, "no %s, so sops has no creation rule "+
			"and refuses to encrypt a new file in the secrets directory", current)
	}
}

// diagnoseSopsRecipients answers who can decrypt what the secrets directory
// will hold next.
//
// The keeper's own recipient is the one that has to be there: without it the
// broker cannot read the next value, and it starts and reports healthy anyway.
// Every other difference is a backup key that turns out to open nothing.  init
// writes this file once, so a key restored or re-minted leaves the rule naming
// the recipient it used to have.
func diagnoseSopsRecipients(report *DoctorReport, opts DoctorOptions, path string) {
	listed, err := sopsRecipients(path)
	if err != nil {
		report.add("sops config", StatusFailed, "%s does not parse (%v), so who can "+
			"decrypt the secrets directory is unknown here. sops has to read this file too", path, err)
		return
	}
	if len(listed) == 0 {
		report.add("sops config", StatusWarn, "%s lists no age recipient, so sops "+
			"encrypts a new file in the secrets directory to nobody and refuses", path)
		return
	}
	// The key is 0400 and the keeper's, so this answers only under sudo, and is
	// reported as unchecked rather than as a pass.
	keyPath := filepath.Join(opts.ConfigDir, "age.key")
	keeper, err := agekey.Recipient(keyPath)
	if err != nil {
		report.unasked("sops config", 1, "%s lists %s, and whether %s is among "+
			"them went unchecked: %v. Re-run as root", path, strings.Join(listed, ", "),
			keyPath, err)
		return
	}
	// Warn, not failed: the values already in the secrets directory still decrypt,
	// so this is a host that works today and cannot take a new value tomorrow.
	if !slices.Contains(listed, keeper) {
		report.add("sops config", StatusWarn, "%s lists %s, none of which is the "+
			"recipient of %s (%s). Every value encrypted into the secrets directory from now on is "+
			"one %s cannot decrypt, and a broker that loads nothing still starts. Add it "+
			"under `- age:`, then re-key each existing file with sops updatekeys",
			path, strings.Join(listed, ", "), keyPath, keeper, opts.KeeperUser)
		return
	}
	report.add("sops config", StatusOK, "%s, %d recipient(s) including %s's",
		path, len(listed), opts.KeeperUser)
}

// diagnoseLogRotation asks whether anything bounds the audit log.
//
// [audit] max_record_bytes bounds one record, and nothing in faramir bounds the
// file: rotation is logrotate's, which is a program that has to be installed,
// has to name this log, and has to be run on it.  Worth a check of its own
// because the install writes the config whether or not the program exists, so
// the step reports "changed" on a host where it does nothing, and because the
// account that fills the log is the one this whole install exists to bound: a
// brokered command's output is what a record carries, so an agent that prints
// enough writes the disk full, and a full disk is where brokered commands stop
// running at all.
//
// Every question here is asked of what is on disk rather than of the install's
// own intentions, because each of them has an answer that looks exactly like a
// working rotation from the install's side: a rule bounding the path config.toml
// named before it was edited, and a rule no run of logrotate ever reads, both
// leave the file present, the program installed and the log growing.
//
// The first two questions read a path and a $PATH and ask no account anything.
// The last two read logrotate's state and the log itself, which belong to root
// and to the broker, so a caller without root is told they went unasked rather
// than given the pass they would otherwise infer from a stat that failed.
func diagnoseLogRotation(report *DoctorReport, cfg *config.Config) {
	if cfg == nil || cfg.Audit.LogPath == "" {
		return
	}
	logPath := cfg.Audit.LogPath
	if !exists(logrotateConfig) {
		report.add("log rotation", StatusFailed, "%s does not exist, so nothing "+
			"bounds %s. Re-run `faramir init`, or bound it some other way",
			logrotateConfig, logPath)
		return
	}
	if _, err := exec.LookPath("logrotate"); err != nil {
		report.add("log rotation", StatusFailed, "%s exists and logrotate does not, "+
			"so it is inert and %s grows without a ceiling. Install logrotate, or "+
			"bound that file some other way", logrotateConfig, logPath)
		return
	}

	// The rule has to name the file the broker appends to.  Both are rendered
	// from one layout, so they agree wherever init wrote them together and part
	// wherever [audit] log_path was moved afterwards, which leaves the rule
	// bounding a path nothing writes and the log growing under the old name.
	named, err := logrotateLogs(logrotateConfig)
	switch {
	case err != nil:
		report.add("log rotation", StatusFailed, "%s cannot be read (%v), so whether "+
			"anything bounds %s cannot be established", logrotateConfig, err, logPath)
		return
	case len(named) == 0:
		report.add("log rotation", StatusWarn, "%s names no log file, so it is empty "+
			"or written in a form this check cannot read. Confirm it covers %s with "+
			"`logrotate -d %s`", logrotateConfig, logPath, logrotateConfig)
		return
	case !logrotateCovers(named, logPath):
		report.add("log rotation", StatusFailed, "%s bounds %s and the broker appends "+
			"to %s, so nothing bounds the log this host writes. Point [audit] "+
			"log_path back at the rotated file, or re-run `faramir init` to rewrite "+
			"the rule", logrotateConfig, strings.Join(named, ", "), logPath)
		return
	}

	// What logrotate has processed, which is the only account of whether the rule
	// is read by the runs that happen rather than merely installed.  A rule the
	// include line does not reach, or one a syntax error earlier in the set
	// abandons, is skipped every run and says nothing about it anywhere else.
	statePath := firstExisting(logrotateStatePaths)
	if statePath == "" {
		report.add("log rotation", StatusWarn, "logrotate keeps no state at %s, so it "+
			"has not run on this host and %s is bounded by a rule nothing has applied. "+
			"Check the logrotate timer or cron job",
			strings.Join(logrotateStatePaths, " or "), logPath)
		return
	}
	rotated, err := logrotateStateLogs(statePath)
	switch {
	case os.IsPermission(err):
		report.unasked("log rotation", 1, "run doctor as root to ask the rest: %s "+
			"says which logs logrotate has processed and %s is the broker's, so "+
			"whether the rule is being applied and how large the log has grown are "+
			"both root's to read. %s does name %s",
			statePath, logPath, logrotateConfig, logPath)
		return
	case err != nil:
		report.add("log rotation", StatusFailed, "%s cannot be read (%v), so whether "+
			"logrotate has ever applied %s cannot be established",
			statePath, err, logrotateConfig)
		return
	case !slices.Contains(rotated, logPath):
		report.add("log rotation", StatusWarn, "%s names %d logs and not %s, so "+
			"logrotate has not applied the rule to it. A host whose first run has not "+
			"come round yet is the ordinary reason; past that, %s is not being read. "+
			"Check the logrotate timer or cron job",
			statePath, len(rotated), logPath, logrotateConfig)
		return
	}

	// The config says 16MB, so a log far past it is one logrotate is not being
	// run on, whatever is installed.  A multiple rather than the number itself:
	// rotation is scheduled rather than continuous, and a log over the size
	// between two runs is ordinary.
	const rotateSize = 16 << 20
	info, err := os.Stat(logPath)
	switch {
	case os.IsPermission(err):
		report.unasked("log rotation", 1, "run doctor as root to ask the last of "+
			"this: %s is the broker's, so its size is root's to read. %s does name "+
			"it, and %s records that logrotate has applied the rule",
			logPath, logrotateConfig, statePath)
		return
	// Absent is not a fault: the rule is missingok and the broker opens the file
	// with O_CREATE, so the next record makes it again.
	case err == nil && info.Size() > 4*rotateSize:
		report.add("log rotation", StatusWarn, "%s is %d bytes, well past the %d "+
			"the rule rotates at, so logrotate is installed and is not being run on "+
			"it. Check the logrotate timer or cron job",
			logPath, info.Size(), rotateSize)
		return
	}
	report.add("log rotation", StatusOK, "%s bounds %s, logrotate is installed to "+
		"apply it, and %s records that it has", logrotateConfig, logPath, statePath)
}

// logrotateLogs is the log files a rule file names: every path outside a
// directive block, which is where logrotate takes its file list from.
//
// A parser rather than `logrotate -d`, whose answer is prose that differs
// between versions.  It reads the form init writes and the forms a hand edit
// produces: several paths to one block, quoted paths, comments, globs.  Blocks
// are skipped by brace depth, so a postrotate script carrying braces of its own
// is the one edit that can hide a path from this, and finding none at all is
// reported as a rule that could not be read rather than as one that misses the
// log.
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
		for _, field := range strings.Fields(line) {
			// logrotate lexes the brace as its own token, so a path can carry one
			// with no space between them.
			if trimmed := strings.TrimSuffix(field, "{"); trimmed != field {
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
// broker writes.  Globs count: a rule may name /var/log/faramir/*.log, which
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
// log it has processed.  One line per log, the path first and quoted since
// version 2, then the date it was last rotated -- which is not read here: a
// quiet log is not rotated at all under notifempty, so the date says how busy
// the host has been rather than whether the rule is applied, and how large the
// log has grown answers that better.
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
		report.unasked("sockets", len(sockets), "systemd is not running here, so whether "+
			"%d socket unit(s) are listening was not asked", len(sockets))
		return
	}
	// What the caller saw before it opened the broker socket, where it sampled.
	// Reading the state here instead would read it after that round trip, which
	// starts any socket the broker depends on: the fault repairs itself between
	// arriving and looking, and all three report as listening.
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
			report.add("sockets", StatusFailed, "%s is %s; check journalctl -u %s",
				socket, state, socket)
			continue
		}
		report.add("sockets", StatusOK, "%s is listening", socket)
	}
}

// diagnoseVersion compares the running broker against the binary asking.  They
// diverge when a new binary was installed and the daemons were not restarted
// onto it, which every other finding here would then describe wrongly: the
// checks read this build's paths, modes and config rules against a host running
// the previous one.
//
// A fail rather than a warn.  Nothing is wrong with either build; what is wrong
// is that an upgrade did not finish, and re-running init is what finishes it.
func diagnoseVersion(report *DoctorReport, opts DoctorOptions) {
	switch {
	case opts.BrokerVersion == "":
		report.unasked("version", 1, "the broker did not answer, so which build "+
			"is running is unknown; this binary is %s", version.Version)
	case opts.BrokerVersion != version.Version:
		report.add("version", StatusFailed, "the broker is running %s and this binary "+
			"is %s, so the daemons were never restarted onto what is installed and "+
			"every finding below describes the wrong build. Run `sudo faramir init`",
			opts.BrokerVersion, version.Version)
	default:
		report.add("version", StatusOK, "broker and binary are both %s", version.Version)
	}
}

// diagnoseBroker asks the broker what it can do.  A value absent from the set
// is neither injectable nor redacted, so a broker serving zero refs from a
// secrets directory that exists is protecting nothing and looks healthy.
//
// Run as the broker's own uid, which is why this needs root: --check opens the
// keeper socket, the SSH keys and the secrets files itself, and root and an
// ordinary account each get a different answer.
func diagnoseBroker(report *DoctorReport, configFile, brokerUser string) brokerServes {
	if os.Geteuid() != 0 {
		report.unasked("broker", 1, "run doctor as root to ask this: --check "+
			"has to run as %s, and any other account gets an answer that is not "+
			"the broker's", brokerUser)
		return servesUnknown
	}
	run := &runner{}
	// Read the report before the exit code is judged.  --check exits non-zero on
	// every state below, so trusting the status alone would report all of them
	// as one unexplained failure.
	out, checkErr := run.command("runuser", "-u", brokerUser, "--",
		filepath.Join(DefaultBinDir, "faramir"), "broker", "-c", configFile, "--check")
	var check checkReport
	if err := json.Unmarshal([]byte(out), &check); err != nil {
		if checkErr != nil {
			report.add("broker", StatusFailed, "--check failed as %s: %v", brokerUser, checkErr)
			return servesUnknown
		}
		report.add("broker", StatusFailed, "could not read the --check report: %v", err)
		return servesUnknown
	}
	// Every one of these fails.  The daemon is more forgiving on purpose, coming
	// up while the secrets are not written yet and refusing exec and redact until
	// they are; doctor is the audit, and a broker serving nothing is what an
	// operator ran it to be told about.
	explained := true
	switch {
	case len(check.Secrets.Patterns) == 0:
		report.add("secrets", StatusFailed, "no managed sops files are configured, so "+
			"nothing is injectable and nothing is redacted")
	case len(check.Secrets.UnresolvedPatterns) > 0:
		// The unresolved entries alone: another pattern beside them may have
		// matched and loaded, and naming that one too would say the untrue thing.
		report.add("secrets", StatusFailed, "%s. Either the secrets have not been "+
			"written yet, or they are on a filesystem that is not mounted; %d ref(s) "+
			"loaded from what did resolve",
			strings.Join(check.Secrets.UnresolvedPatterns, "; "), check.Secrets.Count)
	case check.Secrets.Count == 0:
		report.add("secrets", StatusFailed, "read %s and loaded no refs. %s",
			strings.Join(check.Secrets.Files, ", "), loadErrorDetail(check.Secrets.Errors))
	default:
		report.add("secrets", StatusOK, "%d ref(s) from %d file(s)",
			check.Secrets.Count, len(check.Secrets.Files))
		explained = false
	}
	// Refs the store read and the redactor refused.  Named here rather than left
	// to the fallback below, which would report the one condition --check
	// describes precisely as one it cannot explain.  A warning, not a failure:
	// they are never injected, so what is wrong is that a ref does not work, not
	// that the install is failing to hold a boundary.
	if len(check.Secrets.NotRedactable) > 0 {
		report.add("redaction", StatusWarn, "%d ref(s) are shorter than [secrets] "+
			"min_length, so they are never injected and never redacted: %s. Lengthen "+
			"them with `faramir edit`",
			len(check.Secrets.NotRedactable), check.refusedRefs())
		if check.onlyNotRedactable() {
			explained = true
		}
	}
	// --check fails for reasons the switch does not cover: an unusable [ssh] key,
	// a bound socket with world bits.  Judged on whether this function accounted
	// for the exit code rather than on whether anything else in the report
	// failed, which would swallow this one whenever another check had already
	// failed for reasons of its own.
	if checkErr != nil && !explained {
		report.add("broker", StatusFailed, "--check failed as %s for a reason not "+
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
// reading the key off disk, and asks as the operator, root not being in the
// client group the broker checks against.
//
// Skipped when no key is configured: that is the host where SSH is arranged for
// the executor's uid some other way, and `ssh-add -l` there exits non-zero
// because no agent is running, which is not a fault to report.
//
// Not skipped for want of root: the probe runs as the caller's own account,
// which is the operator either way.  Deciding the skip and reading the answer
// are split out so both can be tested without a broker.
func diagnoseSSHAgent(report *DoctorReport, opts DoctorOptions, cfg *config.Config, serves brokerServes) {
	if cfg == nil || cfg.Ssh.Key == "" {
		report.add("ssh agent", StatusOK, "no [ssh] key configured, so no agent runs "+
			"and none is expected")
		return
	}
	if reason := skipSSHProbe(serves, opts.BrokerVersion); reason != "" {
		report.unasked("ssh agent", 1, "%s", reason)
		return
	}
	out, err := asOperator(opts, filepath.Join(DefaultBinDir, "faramir"),
		"run", "--quiet", "--", "ssh-add", "-l")
	reportSSHProbe(report, cfg, serves, out, err)
}

// skipSSHProbe reports why the probe cannot be put, empty when it can.  The
// probe sends a brokered command, so a broker that refuses one and a broker
// that answers nothing are both states where there is no answer to be had, and
// reporting either as the agent's own fails a host whose agent is fine.
//
// The established refusal first: it names the fault to fix.  An empty version
// is what the install lookup got from a broker that is not running, which the
// sockets and version checks report.
func skipSSHProbe(serves brokerServes, brokerVersion string) string {
	switch {
	case serves == servesNothing:
		return sshAgentRefused
	case brokerVersion == "":
		return sshAgentUnanswered
	}
	return ""
}

// reportSSHProbe turns the probe's answer into a finding.
//
// A refusal from a broker --check found holding values is the one answer that
// is neither the agent's nor a skip: --check reads the managed files itself, so
// a daemon refusing what those files cover is one that came up before they were
// written.
func reportSSHProbe(report *DoctorReport, cfg *config.Config, serves brokerServes, out string, err error) {
	switch classifySSHProbe(out, err) {
	case sshProbeHasKey:
		report.add("ssh agent", StatusOK, "holds a usable key")
	case sshProbeRefused:
		if serves == servesValues {
			report.add("ssh agent", StatusFailed, "the broker refuses brokered commands "+
				"though --check read every managed file as the broker: the running daemon "+
				"came up before the values were there and has not read them since. "+
				"Restart faramir-broker")
			return
		}
		report.unasked("ssh agent", 1, "%s", sshAgentRefused)
	case sshProbeEmpty:
		report.add("ssh agent", StatusFailed, "the agent holds nothing, though [ssh] "+
			"key names %s, so every brokered command that reaches a managed host "+
			"fails to authenticate. Place the key and restart faramir-broker",
			cfg.Ssh.Key)
	default:
		report.add("ssh agent", StatusFailed, "could not ask the broker: %v: %s",
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

// classifySSHProbe reads the probe's answer.
//
// Success first: ssh-add exits non-zero both when the agent is empty and when
// it could not be reached, so err alone does not say which and the output
// decides.  The refusal is the broker declining to run the probe at all, a
// statement about the value set rather than about the agent.
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

// diagnoseGroup lists members of the two groups that grant something, which
// this install does not account for.  Reported rather than removed: whose grant
// that is, is not this command's to decide, and `init` adds to these groups but
// has never taken anything out of one it did not create.
//
// Both groups, because both survive a re-run that renames what they are for.
// Changing --client-group leaves the old group intact with every member; naming
// a new --keeper-user leaves the retired account in the group that owns the
// ciphertext.  Nothing else on this host reports either, and the standing grant
// is what is left of an account the install has otherwise stopped using.
func diagnoseGroup(report *DoctorReport, opts DoctorOptions) {
	// Held as a list so the bail-out below can say how many went unasked: on a
	// host with a --secrets-group of its own there are two, and a count written
	// out separately would report one.
	type granting struct{ label, name, grants string }
	groups := []granting{
		{"group", opts.ClientGroup,
			"reach the broker socket, and enter a tree enrolled with it"},
	}
	// The second only when it is a group of its own.  Defaulted, the secrets group
	// IS the keeper's primary group, and the keeper being in it is the arrangement
	// rather than a leftover; the loop below would name every retired keeper
	// correctly and the current one too.
	if opts.SecretsGroup != "" && opts.SecretsGroup != opts.ClientGroup {
		groups = append(groups, granting{"secrets group", opts.SecretsGroup,
			"read and replace the ciphertext in the secrets directory"})
	}
	// Without the operator's name there is no way to tell the account this install
	// deliberately admitted from one left behind, and the operator IS a member of
	// the client group by construction.  Reporting it as a leftover would print
	// `gpasswd -d <the operator> <the client group>` as the remedy, which is the
	// one change that shuts the agent out of the broker socket.
	if opts.OperatorUser == "" {
		report.unasked("group", len(groups), "the operator account is not named, so a "+
			"member of %s cannot be told from an account left behind: pass "+
			"--operator-user, or run through sudo so SUDO_USER carries it",
			opts.ClientGroup)
		return
	}
	known := []string{opts.OperatorUser, opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	for _, group := range groups {
		diagnoseGroupOutsiders(report, group.label, group.name, known, group.grants)
	}
}

// diagnoseGroupOutsiders is one group's membership against the accounts this
// install uses.
//
// Primary membership as well as supplementary: /etc/group lists only the
// second, and an account whose primary group IS this one holds it without
// appearing there.  That is exactly the shape a renamed --keeper-user leaves,
// the secrets group defaulting to the keeper's own group, so reading the member
// list alone would report the one case worth reporting as clean.
func diagnoseGroupOutsiders(report *DoctorReport, label, name string, known []string, grants string) {
	gid, members, err := groupEntry(name)
	if err != nil {
		report.add(label, StatusFailed, "no group %q, so nothing can %s", name, grants)
		return
	}
	primary, err := primaryMembers(gid)
	if err != nil {
		report.add(label, StatusFailed, "could not read who holds %s as a primary "+
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
		report.add(label, StatusOK, "%s has no unexpected members", name)
		return
	}
	report.add(label, StatusWarn, "%s has members this install does not use: %s. "+
		"Membership is what lets them %s, so an account the install has stopped "+
		"naming is a standing grant. Drop one with: gpasswd -d <account> %s, or "+
		"usermod -g <other> <account> where it is the primary group",
		name, strings.Join(outsiders, ", "), grants, name)
}

// passwdFile is where the accounts are.  A variable so a test can point at one
// it wrote, as loginDefs and shadowFile are.
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

// groupFile is where the groups are.  A variable so a test can point at one it
// wrote, as loginDefs and shadowFile are.
var groupFile = "/etc/group"

// groupEntry is a group's gid and its supplementary members, read from the same
// line.  Both, because the gid is what the primary members are found by, and
// looking it up separately through the system would answer for a different file
// from the one the members came out of.
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
// rather than the ones a default would name.
//
// Every check below asks what a named account can reach, so a name that is not
// the one running answers a question nobody asked and answers it confidently:
// on a host installed with --keeper-user other, defaulting to faramir-keeper
// reports the boundaries of an account that does not exist.
//
// The unit is the source of truth for a service account, being what systemd
// reads; the config for the client group, being what the broker checks; and the
// secrets directory's own group for the secrets group, being what the modes are
// actually set to.  A flag still wins, for a host whose install is not the one
// on this machine.
//
// Failing rather than falling back, and stopping rather than carrying on: each
// of these is readable on any working install, so not reading one means the
// install is broken, and every finding after it would name an account this host
// may not have.
func resolveIdentities(report *DoctorReport, opts DoctorOptions, cfg *config.Config) (DoctorOptions, bool) {
	for _, role := range []struct {
		unit string
		into *string
		flag string
	}{
		{"faramir-broker.service", &opts.BrokerUser, "--broker-user"},
		{"faramir-keeper.service", &opts.KeeperUser, "--keeper-user"},
		{"faramir-exec.service", &opts.ExecUser, "--exec-user"},
	} {
		if *role.into != "" {
			continue
		}
		account, err := unitUser(role.unit)
		if err != nil {
			report.add("identities", StatusFailed, "cannot tell which account runs "+
				"%s (%v), so nothing below could be asked about the right one. Reinstall, "+
				"or pass %s", role.unit, err, role.flag)
			return opts, false
		}
		*role.into = account
	}

	if opts.ClientGroup == "" {
		if cfg.Server.AllowedGroup == "" {
			report.add("identities", StatusFailed, "[server] allowed_group is unset, so "+
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
			report.add("identities", StatusFailed, "cannot read the group owning %s "+
				"(%v), which is what keeps every account but the keeper out of the "+
				"ciphertext. Reinstall, or pass --secrets-group", dir, err)
			return opts, false
		}
		opts.SecretsGroup = group
	}

	report.add("identities", StatusOK, "%s, %s, %s, in %s, secrets owned by %s",
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
