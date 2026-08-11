package install

import (
	"encoding/json"
	"fmt"
	"os"
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
	diagnoseUnits(&report)
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
			"and the secrets directory is globbed by [secrets] files. Move it: sudo mv %s %s",
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
		report.NotAsked++
		report.add("sops config", StatusWarn, "%s lists %s, and whether %s is among "+
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

// diagnoseUnits reports the sockets, not the services: all three are socket
// activated, so an inactive service is ordinary.
func diagnoseUnits(report *DoctorReport) {
	if !systemdRunning() {
		report.add("sockets", StatusWarn, "systemd is not running here")
		return
	}
	run := &runner{}
	for _, socket := range sockets {
		out, err := run.command("systemctl", "is-active", socket)
		state := strings.TrimSpace(out)
		if state == "" {
			// systemctl prints the state even when it exits non-zero, so an empty
			// answer is systemctl itself having failed.  Named, or the finding reads
			// "<socket> is ;".
			state = "unreportable"
		}
		if err != nil || state != "active" {
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
		report.add("version", StatusWarn, "the broker did not answer, so which build "+
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
		report.NotAsked++
		report.add("broker", StatusWarn, "run doctor as root to ask this: --check "+
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
	// --check fails for reasons the switch does not cover: an unusable [ssh] key,
	// a ref refused as not redactable, a bound socket with world bits.  Judged on
	// whether this function accounted for the exit code rather than on whether
	// anything else in the report failed, which would swallow this one whenever
	// another check had already failed for reasons of its own.
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
		report.NotAsked++
		report.add("ssh agent", StatusWarn, "%s", reason)
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
		report.NotAsked++
		report.add("ssh agent", StatusWarn, "%s", sshAgentRefused)
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
	// Without the operator's name there is no way to tell the account this install
	// deliberately admitted from one left behind, and the operator IS a member of
	// the client group by construction.  Reporting it as a leftover would print
	// `gpasswd -d <the operator> <the client group>` as the remedy, which is the
	// one change that shuts the agent out of the broker socket.
	if opts.OperatorUser == "" {
		report.NotAsked++
		report.add("group", StatusWarn, "the operator account is not named, so a "+
			"member of %s cannot be told from an account left behind: pass "+
			"--operator-user, or run through sudo so SUDO_USER carries it",
			opts.ClientGroup)
		return
	}
	known := []string{opts.OperatorUser, opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	diagnoseGroupOutsiders(report, "group", opts.ClientGroup, known,
		"reach the broker socket, and enter a tree enrolled with it")
	// Only when it is a group of its own.  Defaulted, the secrets group IS the
	// keeper's primary group, and the keeper being in it is the arrangement rather
	// than a leftover; the loop below would name every retired keeper correctly and
	// the current one too.
	if opts.SecretsGroup != "" && opts.SecretsGroup != opts.ClientGroup {
		diagnoseGroupOutsiders(report, "secrets group", opts.SecretsGroup, known,
			"read and replace the ciphertext in the secrets directory")
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

// groupMembers reads a group's supplementary members; primary membership does
// not appear there.
func groupMembers(name string) ([]string, error) {
	_, members, err := groupEntry(name)
	return members, err
}

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

// systemUnitDir is where the units are installed.  A variable so a test can
// point at a directory it wrote, as loginDefs and shadowFile are.
var systemUnitDir = "/etc/systemd/system"

// unitUser reads User= out of an installed unit.  Parsed rather than asked of
// systemctl, which reports the running unit and answers nothing when the daemon
// is down, which is one of the states worth examining.
func unitUser(name string) (string, error) {
	path := filepath.Join(systemUnitDir, name)
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		if account, ok := strings.CutPrefix(strings.TrimSpace(line), "User="); ok {
			if account = strings.TrimSpace(account); account != "" {
				return account, nil
			}
		}
	}
	return "", fmt.Errorf("%s names no User=", path)
}

// unitConfigDir is the config directory the installed broker unit loads, or ""
// when there is no unit or it names none.  Read from the unit rather than asked
// of a running broker: a host whose daemons are down still has an install, and
// this is the question of where that install is.
//
// Drop-ins as well as the unit, in the order systemd reads them: a
// <unit>.d/*.conf setting Environment=FARAMIR_CONFIG is what the daemons
// actually load, and uninstall removes those directories, so they are a state
// this install expects rather than one only an operator could have made.
// Reading the main file alone would see no move where there is one, and
// re-provision a directory nothing loads.
func unitConfigDir(name string) string {
	dir := ""
	for _, path := range unitFiles(name) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line),
				"Environment=FARAMIR_CONFIG="); ok {
				// An empty assignment is systemd's way of unsetting, so it clears what an
				// earlier file said rather than being skipped as "names none".
				if value = strings.TrimSpace(value); value == "" {
					dir = ""
					continue
				}
				dir = filepath.Dir(value)
			}
		}
	}
	return dir
}

// unitFiles is a unit and its drop-ins, in the order systemd applies them: the
// unit first, then <unit>.d/*.conf sorted by name, later winning.
func unitFiles(name string) []string {
	files := []string{filepath.Join(systemUnitDir, name)}
	entries, err := os.ReadDir(filepath.Join(systemUnitDir, name+".d"))
	if err != nil {
		return files
	}
	var dropIns []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			dropIns = append(dropIns, filepath.Join(systemUnitDir, name+".d", entry.Name()))
		}
	}
	slices.Sort(dropIns)
	return append(files, dropIns...)
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
