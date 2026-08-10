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
}

// Status is a finding's verdict.  Three levels, because a broker that is
// running and holding nothing is neither a pass nor a fail.
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
type Status string

const (
	StatusOK     Status = "ok"
	StatusWarn   Status = "warn"
	StatusFailed Status = "failed"
)

// Finding is one check.
type Finding struct {
	Name   string `json:"check"`
	Status Status `json:"status"`
	Detail string `json:"detail,omitempty"`
}

// DoctorReport is the whole examination; Failed is the exit code a caller
// reads.
type DoctorReport struct {
	Failed   bool      `json:"failed"`
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

// Diagnose reports whether an install is doing its job -- the questions the
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

	diagnoseUnits(&report)
	servesCommands := diagnoseBroker(&report, configFile, opts.BrokerUser)
	diagnoseSSHAgent(&report, opts, cfg, servesCommands)
	diagnoseGroup(&report, opts)
	diagnoseSopsConfig(&report, opts)
	diagnoseBoundaries(&report, opts, cfg, servesCommands)
	return report
}

// diagnoseSopsConfig reports a creation rule left inside the secrets directory.
// sops takes the first .sops.yaml it finds walking up from the working
// directory, so a copy in the secrets directory shadows the one above it and
// new values encrypt to different recipients depending on where the operator
// was standing.
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
		if err != nil || state != "active" {
			report.add("sockets", StatusFailed, "%s is %s; check journalctl -u %s",
				socket, state, socket)
			continue
		}
		report.add("sockets", StatusOK, "%s is listening", socket)
	}
}

// diagnoseBroker asks the broker what it can do.  A value absent from the set
// is neither injectable nor redacted, so a broker serving zero refs from a
// store that exists is protecting nothing and looks healthy.
//
// Run as the broker's own uid, which is why this needs root: --check opens the
// keeper socket, the SSH keys and the secrets files itself, and root and an
// ordinary account each get a different answer.
func diagnoseBroker(report *DoctorReport, configFile, brokerUser string) (servesCommands bool) {
	if os.Geteuid() != 0 {
		report.add("broker", StatusWarn, "run doctor as root to ask this: --check "+
			"has to run as %s, and any other account gets an answer that is not "+
			"the broker's", brokerUser)
		return false
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
			return false
		}
		report.add("broker", StatusFailed, "could not read the --check report: %v", err)
		return false
	}
	// Every one of these fails.  The daemon is more forgiving on purpose, coming
	// up while the secrets are not written yet and refusing exec and redact until
	// they are; doctor is the audit, and a broker serving nothing is what an
	// operator ran it to be told about.
	switch {
	case len(check.Secrets.Patterns) == 0:
		report.add("secrets", StatusFailed, "no managed sops files are configured, so "+
			"nothing is injectable and nothing is redacted")
	case len(check.Secrets.Unresolved) > 0:
		report.add("secrets", StatusFailed, "%s named no file, so nothing is "+
			"injectable and nothing is redacted. Either the secrets have not been "+
			"written yet, or they are on a filesystem that is not mounted: %s",
			strings.Join(check.Secrets.Patterns, ", "),
			strings.Join(check.Secrets.Unresolved, "; "))
	case check.Secrets.Count == 0:
		report.add("secrets", StatusFailed, "read %s and loaded no refs. %s",
			strings.Join(check.Secrets.Files, ", "), loadErrorDetail(check.Secrets.Errors))
	default:
		report.add("secrets", StatusOK, "%d ref(s) from %d file(s)",
			check.Secrets.Count, len(check.Secrets.Files))
	}
	if checkErr != nil && !report.Failed {
		report.add("broker", StatusFailed, "--check failed as %s: %v", brokerUser, checkErr)
	}
	// The broker refuses every brokered command while it holds nothing, so a
	// probe that runs one would report the empty store as whatever it was
	// probing for.
	return check.Secrets.Count > 0
}

// diagnoseSSHAgent asks what a brokered command would actually get, rather than
// reading the key off disk, and asks as the operator, root not being in the
// client group the broker checks against.
//
// Skipped when no key is configured: that is the host where SSH is arranged for
// the executor's uid some other way, and `ssh-add -l` there exits non-zero
// because no agent is running, which is not a fault to report.
//
// Skipped too when the broker serves no commands, the probe being one: the
// refusal is about the value set and is reported as that.
func diagnoseSSHAgent(report *DoctorReport, opts DoctorOptions, cfg *config.Config, servesCommands bool) {
	if cfg == nil || cfg.Ssh.Key == "" {
		report.add("ssh agent", StatusOK, "no [ssh] key configured, so no agent runs "+
			"and none is expected")
		return
	}
	if !servesCommands {
		report.add("ssh agent", StatusWarn, "not asked: the broker holds no managed "+
			"values, so it refuses the brokered command this probe runs")
		return
	}
	out, err := asOperator(opts, filepath.Join(DefaultBinDir, "faramir"),
		"run", "--quiet", "--", "ssh-add", "-l")
	// Success first: ssh-add exits non-zero both when the agent is empty and
	// when it could not be reached, so err alone does not say which.
	switch {
	case strings.Contains(out, "SHA256"):
		report.add("ssh agent", StatusOK, "holds a usable key")
	case strings.Contains(out, "no identities"):
		report.add("ssh agent", StatusFailed, "the agent holds nothing, though [ssh] "+
			"key names %s, so every brokered command that reaches a managed host "+
			"fails to authenticate. Place the key and restart faramir-broker",
			cfg.Ssh.Key)
	default:
		report.add("ssh agent", StatusFailed, "could not ask the broker: %v: %s",
			err, strings.TrimSpace(out))
	}
}

// diagnoseGroup lists members of the shared group that this did not create.
// Reported rather than removed: whose grant that is, is not this command's to
// decide.
func diagnoseGroup(report *DoctorReport, opts DoctorOptions) {
	group, err := user.LookupGroup(opts.ClientGroup)
	if err != nil {
		report.add("group", StatusFailed, "no group %q, so nothing can reach the "+
			"broker socket", opts.ClientGroup)
		return
	}
	members, err := groupMembers(group.Name)
	if err != nil {
		report.add("group", StatusFailed, "could not read the members of %s (%v), so "+
			"who reaches the broker went unverified", opts.ClientGroup, err)
		return
	}
	known := []string{opts.OperatorUser, opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	var outsiders []string
	for _, member := range members {
		if member != "" && !slices.Contains(known, member) {
			outsiders = append(outsiders, member)
		}
	}
	if len(outsiders) == 0 {
		report.add("group", StatusOK, "%s has no unexpected members", opts.ClientGroup)
		return
	}
	report.add("group", StatusWarn, "%s has members this install did not create: %s. "+
		"Membership grants read on the secrets directory, so a dead account here is a standing "+
		"grant. Drop one with: gpasswd -d <account> %s",
		opts.ClientGroup, strings.Join(outsiders, ", "), opts.ClientGroup)
}

// groupMembers reads a group's supplementary members; primary membership does
// not appear there.
func groupMembers(name string) ([]string, error) {
	body, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	for line := range strings.Lines(string(body)) {
		fields := strings.Split(strings.TrimSpace(line), ":")
		if len(fields) < 4 || fields[0] != name {
			continue
		}
		if fields[3] == "" {
			return nil, nil
		}
		return strings.Split(fields[3], ","), nil
	}
	return nil, fmt.Errorf("no group %q in /etc/group", name)
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
// may not have.  A wrong answer given confidently is worse here than no answer.
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

// unitUser reads User= out of an installed unit.  Parsed rather than asked of
// systemctl, which reports the running unit and answers nothing when the daemon
// is down, which is one of the states worth examining.
func unitUser(name string) (string, error) {
	path := filepath.Join("/etc/systemd/system", name)
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
