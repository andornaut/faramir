package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agekey"
	"github.com/andornaut/faramir/internal/config"
)

// DoctorOptions is what Diagnose needs to find an install it did not perform.
type DoctorOptions struct {
	ConfigDir string
	Operator  string
	Group     string
	// The three service accounts, so the group audit recognises the ones this
	// install created rather than reporting them as intruders.
	BrokerUser string
	KeeperUser string
	ExecUser   string
	// StoreGroup owns the managed sops files, defaulting to the keeper's own
	// group as install leaves it.
	StoreGroup string
}

// Status is a finding's verdict.  Three levels, because a broker that is
// running and holding nothing is neither a pass nor a fail.
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
	if opts.Group == "" {
		opts.Group = DefaultGroup
	}
	if opts.BrokerUser == "" {
		opts.BrokerUser = DefaultBrokerUser
	}
	if opts.KeeperUser == "" {
		opts.KeeperUser = DefaultKeeperUser
	}
	if opts.ExecUser == "" {
		opts.ExecUser = DefaultExecUser
	}
	if opts.StoreGroup == "" {
		opts.StoreGroup = opts.KeeperUser
	}
	var report DoctorReport
	configFile := filepath.Join(opts.ConfigDir, "config.toml")

	if !exists(configFile) {
		report.add("config", StatusFailed, "%s is missing; the daemons read it at "+
			"startup and exit without one", configFile)
		return report
	}
	report.add("config", StatusOK, "%s", configFile)

	// The daemons' own paths rather than the defaults, or a host whose store
	// and sockets moved is examined at addresses nothing uses.
	cfg, err := config.Load(configFile)
	if err != nil {
		report.add("config", StatusFailed, "%s does not load: %v", configFile, err)
		return report
	}

	diagnoseUnits(&report)
	diagnoseBroker(&report, configFile, opts.BrokerUser)
	diagnoseSSHAgent(&report, opts)
	diagnoseGroup(&report, opts)
	diagnoseSopsConfig(&report, opts)
	diagnoseBoundaries(&report, opts, cfg)
	return report
}

// diagnoseSopsConfig reports a creation rule left inside the store.  sops takes
// the first .sops.yaml it finds walking up from the working directory, so a copy
// in the store shadows the one above it and new values encrypt to different
// recipients depending on where the operator was standing.
//
// Reported rather than moved: answering which is current wrongly writes values
// nothing can decrypt.
func diagnoseSopsConfig(report *DoctorReport, opts DoctorOptions) {
	layout := Layout{ConfigDir: opts.ConfigDir}
	current, stale := layout.SopsConfigPath(), layout.StaleSopsConfigPath()
	switch {
	case exists(stale) && exists(current):
		report.add("sops config", StatusWarn, "%s shadows %s for anything run from "+
			"the store, sops taking the nearest one walking up. Compare the recipients, "+
			"then: sudo rm %s", stale, current, stale)
	case exists(stale):
		report.add("sops config", StatusWarn, "%s is where earlier installs put it, "+
			"and the store is globbed by [secrets] files. Move it: sudo mv %s %s",
			stale, stale, current)
	case exists(current):
		diagnoseSopsRecipients(report, opts, current)
	default:
		report.add("sops config", StatusWarn, "no %s, so sops has no creation rule "+
			"and refuses to encrypt a new file in the store", current)
	}
}

// diagnoseSopsRecipients answers who can decrypt what the store will hold next.
//
// The keeper's own recipient is the one that has to be there: without it the
// broker cannot read the next value, and it starts and reports healthy anyway.
// Every other difference is a backup key that turns out to open nothing.  init
// writes this file once, so a key restored or re-minted leaves the rule naming
// the recipient it used to have.
func diagnoseSopsRecipients(report *DoctorReport, opts DoctorOptions, path string) {
	listed, err := sopsRecipients(path)
	if err != nil {
		report.add("sops config", StatusWarn, "%s does not parse (%v), so who can "+
			"decrypt the store is unknown here. sops has to read this file too", path, err)
		return
	}
	if len(listed) == 0 {
		report.add("sops config", StatusWarn, "%s lists no age recipient, so sops "+
			"encrypts a new file in the store to nobody and refuses", path)
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
	// Warn, not failed: the values already in the store still decrypt, so this
	// is a host that works today and cannot take a new value tomorrow.
	if !slices.Contains(listed, keeper) {
		report.add("sops config", StatusWarn, "%s lists %s, none of which is the "+
			"recipient of %s (%s). Every value encrypted into the store from now on is "+
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
func diagnoseBroker(report *DoctorReport, configFile, brokerUser string) {
	if os.Geteuid() != 0 {
		report.add("broker", StatusWarn, "run doctor as root to ask this: --check "+
			"has to run as %s, and any other account gets an answer that is not "+
			"the broker's", brokerUser)
		return
	}
	run := &runner{}
	out, err := run.command("runuser", "-u", brokerUser, "--",
		filepath.Join(DefaultBinDir, "faramir"), "broker", "-c", configFile, "--check")
	if err != nil {
		report.add("broker", StatusFailed, "--check failed as %s: %v", brokerUser, err)
		return
	}
	var check checkReport
	if err := json.Unmarshal([]byte(out), &check); err != nil {
		report.add("broker", StatusFailed, "could not read the --check report: %v", err)
		return
	}
	switch {
	case len(check.Secrets.Patterns) == 0:
		report.add("secrets", StatusWarn, "no managed sops files are configured, so "+
			"nothing is injectable and nothing is redacted")
	case len(check.Secrets.Files) == 0:
		report.add("secrets", StatusWarn, "%s named no file, so nothing is "+
			"injectable and nothing is redacted. Either the store has not been "+
			"written yet, or it is on a filesystem that is not mounted",
			strings.Join(check.Secrets.Patterns, ", "))
	case check.Secrets.Count == 0:
		report.add("secrets", StatusFailed, "read %s and loaded no refs. %s",
			strings.Join(check.Secrets.Files, ", "), loadErrorDetail(check.Secrets.Errors))
	default:
		report.add("secrets", StatusOK, "%d ref(s) from %d file(s)",
			check.Secrets.Count, len(check.Secrets.Files))
	}
}

// diagnoseSSHAgent is the other way an install comes up healthy and does
// nothing: the broker only warns when no key loads, so a missing one leaves
// every socket active and every playbook unable to reach a host.
//
// Asked through the broker rather than read off disk, what matters being what a
// brokered command gets, and asked as the operator, root not being in the
// shared group the broker checks against.
func diagnoseSSHAgent(report *DoctorReport, opts DoctorOptions) {
	out, err := asOperator(opts, filepath.Join(DefaultBinDir, "faramir"),
		"run", "--quiet", "--", "ssh-add", "-l")
	switch {
	case err != nil:
		report.add("ssh agent", StatusWarn, "could not ask the broker: %v", err)
	case strings.Contains(out, "SHA256"):
		report.add("ssh agent", StatusOK, "holds a usable key")
	default:
		report.add("ssh agent", StatusWarn, "holds no key, so brokered commands "+
			"reach no managed host that expects one")
	}
}

// diagnoseGroup lists members of the shared group that this did not create.
// Reported rather than removed: whose grant that is, is not this command's to
// decide.
func diagnoseGroup(report *DoctorReport, opts DoctorOptions) {
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		report.add("group", StatusFailed, "no group %q, so nothing can reach the "+
			"broker socket", opts.Group)
		return
	}
	members, err := groupMembers(group.Name)
	if err != nil {
		report.add("group", StatusWarn, "could not read the members of %s: %v", opts.Group, err)
		return
	}
	known := []string{opts.Operator, opts.BrokerUser, opts.KeeperUser, opts.ExecUser}
	var outsiders []string
	for _, member := range members {
		if member != "" && !slices.Contains(known, member) {
			outsiders = append(outsiders, member)
		}
	}
	if len(outsiders) == 0 {
		report.add("group", StatusOK, "%s has no unexpected members", opts.Group)
		return
	}
	report.add("group", StatusWarn, "%s has members this install did not create: %s. "+
		"Membership grants read on the store, so a dead account here is a standing "+
		"grant. Drop one with: gpasswd -d <account> %s",
		opts.Group, strings.Join(outsiders, ", "), opts.Group)
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
