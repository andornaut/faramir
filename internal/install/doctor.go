package install

import (
	"encoding/json"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
)

// DoctorOptions is what Diagnose needs to find an install it did not perform.
type DoctorOptions struct {
	ConfigDir string
	Operator  string
	Group     string
	// The three service accounts, so the group audit below recognises the ones
	// this install created.  Left at the defaults they would report every
	// account of a non-default install as an intruder and tell the operator to
	// remove the broker from its own group.
	BrokerUser string
	KeeperUser string
	ExecUser   string
	// StoreGroup owns the managed sops files.  Defaults to the keeper's own
	// group, which is what install leaves it as: the keeper is the only account
	// that opens one of those files.
	StoreGroup string
}

// Status is a finding's verdict.  Three levels rather than pass/fail, because
// the interesting cases here are neither: a broker that is running and holding
// nothing passes every test that asks whether it started.
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

// DoctorReport is the whole examination.  Failed is true when any finding is,
// which is the exit code a caller reads.
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

// Diagnose reports whether an install is doing its job.
//
// It answers the questions the install steps cannot: those check what they
// wrote, and every failure worth catching here is one where everything was
// written correctly and the result still protects nothing.
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

	// Loaded for the paths the checks below ask about, which are the daemons'
	// own rather than the defaults: a host whose store and sockets were moved
	// would otherwise be examined at addresses nothing uses.
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

// diagnoseSopsConfig reports a creation rule left inside the store.
//
// sops resolves .sops.yaml by walking up from the working directory and takes
// the first it finds, so a copy in the store shadows the one in the config
// directory for anything run from in there.  Two rules that have drifted apart
// encrypt new values to different recipients depending on where the operator
// was standing, and neither reports the other.
//
// Reported rather than moved: which of the two is current is a question about
// the recipients in them, and answering it wrongly writes values nothing can
// decrypt.
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
		report.add("sops config", StatusOK, "%s", current)
	default:
		report.add("sops config", StatusWarn, "no %s, so sops has no creation rule "+
			"and refuses to encrypt a new file in the store", current)
	}
}

// diagnoseUnits reports the sockets, not the services: all three are socket
// activated, so an inactive service is ordinary and an inactive socket is the
// install not listening at all.
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

// diagnoseBroker asks the broker what it can actually do.
//
// The keeper decrypts sops and nothing else, so a credential held anywhere else
// is absent from the value set, and a value absent from the set is neither
// injectable nor redacted.  A broker serving zero refs from a store that exists
// is running and protecting nothing, and looks exactly like a healthy install.
//
// Run as the broker's own uid, which is why this needs root.  --check opens the
// keeper socket, the SSH keys and the secrets files itself, and both root and an
// ordinary account get a different answer from the one the broker gets: root
// reads what the broker cannot, and an ordinary account cannot reach the keeper
// at all.
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
// nothing: the broker loads its keys at startup and only warns when none of
// them load, so a missing or unreadable key leaves every socket active and every
// playbook unable to reach a single managed host.
//
// Asked through the broker rather than read off disk, because what matters is
// what a brokered command gets: the executor can use the agent but cannot read
// the key, so this is the only place the answer is visible.
//
// Asked as the operator, because the broker checks the peer's credentials
// against the shared group and root is not in it: this command runs as root for
// everything else, and asking as ourselves would report a broken agent on a
// working install.
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
//
// Membership grants read on the store, so an account nobody recognises is a
// standing grant.  Reported rather than removed: it is not this command's to
// decide whose grant that is.
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

// groupMembers reads a group's supplementary members.  Primary membership does
// not appear there, which is why the accounts are looked up by name elsewhere.
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
