package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/andornaut/faramir/internal/brokercheck"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/runcmd"
	"github.com/andornaut/faramir/internal/version"
)

// Options names the accounts, groups and paths Diagnose examines.
type Options struct {
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
	// release, which stamps none.
	BrokerBuild string

	// SocketStates maps each socket unit to what `systemctl is-active` said
	// before the broker was asked anything. The caller samples it because
	// opening the broker socket activates the service, which Requires= the keeper
	// and executor sockets, so a socket that was down comes up. Empty when the
	// caller did not sample, and then the state is read here.
	SocketStates map[string]string
	// deadProbers is the accounts this run could not ask anything as: the
	// liveness probe against / failed for them, so a refusal from one is the
	// asking failing rather than a boundary holding. Filled by
	// diagnoseBoundaries; askable drops them. Unexported: a probe result, not a
	// caller's setting.
	deadProbers map[string]bool
}

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

// checkConfig names the check the config file gets. The same word the install
// names its own config step with, so an operator reading a report and a run
// sees one subject; the two are separate lists, and neither is derived from the
// other.
const checkConfig = "config"

// Diagnose reports whether an install is doing its job, which the install steps
// cannot answer: everything can be written correctly and still protect
// nothing.
func Diagnose(opts Options) Report {
	if opts.ConfigDir == "" {
		opts.ConfigDir = hostlayout.DefaultConfigDir
	}
	var report Report
	configFile := filepath.Join(opts.ConfigDir, "config.toml")

	// Before anything is examined. Every check that asks what the agent account
	// can reach answers about a uid that is not there, so the report reads as an
	// examination of a host rather than of a name nothing on it has.
	if opts.AgentUser != "" {
		if _, err := hostfs.LookupUser(opts.AgentUser); err != nil {
			report.addf("identities", StatusFailed, "there is no account %q on "+
				"this host, so what the agent can reach was not examined. Name the account "+
				"the coding agent runs as with `faramir init --agent-user`", opts.AgentUser)
			abandoned(&report, "the agent account does not resolve")
			return report
		}
	}

	if !hostfs.Exists(configFile) {
		report.addf(checkConfig, StatusFailed, "%s is missing; the daemons read "+
			"it at startup and exit without it", configFile)
		abandoned(&report, "there is no config to examine against")
		return report
	}
	report.addf(checkConfig, StatusOK, "%s", configFile)

	// The daemons' own paths rather than the defaults, or a host whose store and
	// sockets moved is examined at addresses nothing uses.
	cfg, err := config.Load(configFile)
	if err != nil {
		report.addf(checkConfig, StatusFailed, "%s does not load: %v", configFile, err)
		abandoned(&report, "the config did not load")
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
		abandoned(&report, "the install's identities did not resolve")
		return report
	}

	// The broker probe first, whatever order it is reported in: the ssh agent and
	// boundaries checks both need to know whether the broker serves anything. Its
	// findings are buffered so they still land in name order below.
	var brokerReport Report
	serves := diagnoseBroker(&brokerReport, configFile, opts.BrokerUser)

	ctx := checkCtx{opts: opts, cfg: cfg, serves: serves, broker: brokerReport}
	for _, c := range checks {
		c.run(&report, ctx)
	}
	return report
}

// checkCtx is what every check is handed. One argument rather than the four
// shapes the checks between them want, so the list below reads as an order
// rather than as a call signature per line.
type checkCtx struct {
	opts   Options
	cfg    *config.Config
	serves brokerServes
	// broker is the probe's buffered findings, merged in by the entry that
	// reports them: the probe has to run before the checks that read serves, and
	// is reported in name order among the ones that need root.
	broker Report
}

// check is one entry in the examination.
type check struct {
	// name is what this entry is called in this list, for the ordering test's
	// messages. It is not the name a finding is filed under: several checks file
	// under more than one, and diagnoseBoundaries under a dozen.
	name string
	// needsRoot says the question cannot be put without root, so the check warns
	// rather than answering. The list is ordered on it, which is what makes a run
	// without root read as one block of warnings at the end rather than as gaps
	// between the answers above.
	needsRoot bool
	run       func(*Report, checkCtx)
}

// checks is the examination, in the order a report lists it. A list rather than
// a run of calls so that the ordering, the root grouping and how many checks
// there are altogether are all read off the same place: the count an abandoned
// examination reports is len(checks), which cannot drift from what runs.
//
// What any account can answer comes first, in name order. The ssh agent probe
// runs a brokered command as the caller's own account.
var checks = []check{
	{name: "group", run: func(r *Report, c checkCtx) { diagnoseGroup(r, c.opts) }},
	{name: "log rotation", run: func(r *Report, c checkCtx) { diagnoseLogRotation(r, c.cfg) }},
	{name: "units", run: func(r *Report, c checkCtx) { diagnoseUnits(r, c.opts) }},
	{name: "socket enablement", run: func(r *Report, _ checkCtx) { diagnoseSocketEnablement(r) }},
	{name: "drop-ins", run: func(r *Report, _ checkCtx) { diagnoseDropIns(r) }},
	{name: "memory bounds", run: func(r *Report, _ checkCtx) { diagnoseMemoryBounds(r) }},
	{name: "broker memory", run: func(r *Report, _ checkCtx) { diagnoseBrokerMemory(r) }},
	{name: "ssh agent", run: func(r *Report, c checkCtx) { diagnoseSSHAgent(r, c.opts, c.cfg, c.serves) }},
	{name: "version", run: func(r *Report, c checkCtx) { diagnoseVersion(r, c.opts) }},

	{name: "boundaries", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseBoundaries(r, c.opts, c.cfg, c.serves) }},
	{name: "known hosts", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseKnownHosts(r, c.opts, c.cfg) }},
	{name: "broker probe", needsRoot: true, run: func(r *Report, c checkCtx) { r.merge(c.broker) }},
	{name: "sops config", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseSopsConfig(r, c.opts) }},
	{name: "agent rules", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseAgentRules(r, c.opts) }},
	{name: "hook reach", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseHookReach(r, c.opts) }},
	{name: "codex trust", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseCodexTrust(r, c.opts) }},
	{name: "agent code", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseAgentCode(r, c.opts) }},
	{name: "agent rule drift", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseAgentRuleDrift(r, c.opts) }},
	{name: "linked files", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseLinkedFiles(r, c.opts, c.cfg) }},
	{name: "install rules", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseInstallRules(r, c.opts) }},
	{name: "blocked paths", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseBlockedPaths(r, c.opts, c.cfg) }},
	{name: "linked access", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseLinkedAccess(r, c.opts, c.cfg) }},
	{name: "tree config", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseTreeConfig(r, c.opts) }},
	{name: "tree modes", needsRoot: true, run: func(r *Report, c checkCtx) { diagnoseTreeModes(r, c.opts) }},
	{name: "editable files", needsRoot: true,
		run: func(r *Report, c checkCtx) { diagnoseEditableFiles(r, c.opts) }},
}

// diagnoseVersion compares the running broker against the binary asking. They
// diverge when a new binary was installed and the daemons were not restarted
// onto it, which leaves every other finding describing the wrong build: the
// checks read this build's paths, modes and config rules. A fail rather than a
// warn: an upgrade did not finish, and re-running init is what finishes it.
func diagnoseVersion(report *Report, opts Options) {
	switch {
	case opts.BrokerVersion == "":
		// A broker that is running answers this even when it refuses the
		// request for naming another version, every error naming the build
		// that answered, so nothing here is a broker that is not up.
		report.unaskedf("version", 1, "the broker did not answer, so which build "+
			"is running is unknown; this binary is %s", version.Version)
	case opts.BrokerVersion != version.Version:
		report.addf("version", StatusFailed, "the broker is running %s and this "+
			"binary is %s, so the daemons were never restarted after the install, and "+
			"every check against the broker describes the wrong build. Run `sudo faramir "+
			"init`",
			opts.BrokerVersion, version.Version)
	// Same version, different build. Every unstamped binary reports "dev", so
	// the comparison above passes between two of them and this is what catches
	// a daemon left on the binary it was started from. Both sides have to name
	// a build for the difference to mean anything: a release names none, and
	// neither does a broker older than the field.
	case version.Build != "" && opts.BrokerBuild != "" &&
		opts.BrokerBuild != version.Build:
		report.addf("version", StatusFailed, "the broker and this binary are "+
			"both %s but are different builds, %s against %s, so the daemons were never "+
			"restarted after the install, and every check against the broker describes "+
			"the wrong build. Run `sudo faramir init`",
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
func diagnoseBroker(report *Report, configFile, brokerUser string) brokerServes {
	if os.Geteuid() != 0 {
		report.unaskedf("broker", 1, "--check was not run: it has to run as %s, "+
			"and any other account gets an answer that is not the broker's. Run doctor as "+
			"root", brokerUser)
		return servesUnknown
	}
	// Read the report before the exit code is judged. --check exits non-zero on
	// every state below, so trusting the status alone would report all of them
	// as one unexplained failure.
	// Ten minutes: --check decrypts the whole store, which has its own five
	// minute budget inside, and a broker past this is hung rather than slow.
	out, checkErr := runcmd.OutputWithin(10*time.Minute, "runuser", "-u", brokerUser, "--",
		"env", "FARAMIR_CONFIG="+configFile,
		filepath.Join(hostlayout.DefaultBinDir, "faramir"), "broker", "--check")
	var check brokercheck.CheckReport
	if err := json.Unmarshal([]byte(out), &check); err != nil {
		if checkErr != nil {
			report.addf("broker", StatusFailed, "--check failed as %s: %v", brokerUser, checkErr)
			return servesUnknown
		}
		report.addf("broker", StatusFailed, "could not read the --check report: %v", err)
		return servesUnknown
	}
	return judgeBrokerCheck(report, brokerUser, check, checkErr)
}

// judgeBrokerCheck is diagnoseBroker past the probe: the report parsed and the
// exit judged, split out so what gets named for which exit can be asserted
// without a broker.
func judgeBrokerCheck(report *Report, brokerUser string, check brokercheck.CheckReport,
	checkErr error) brokerServes {
	const store = "secrets store"
	status, detail := storeFinding(check)
	report.addf(store, status, "%s", detail)
	// Whether something in this report named a cause --check exits non-zero
	// for. A failed store finding is one (load errors); a warning is not, an
	// empty or unwritten store being a state --check reports and exits zero
	// over. Socket policy problems are in the report too, under `policy` from
	// diagnoseSocketPolicy's own examination. Several causes at once can still
	// leave one unnamed, which the fallback's %v carries as --check's stderr.
	explained := status == StatusFailed || len(check.Policy) > 0

	// Refs the store read and the redactor refused. Named here rather than left
	// to the fallback below, which would report a condition --check describes
	// precisely as one it cannot explain. A failure: a ref the config names does
	// not answer, which is the same degraded host `faramir status` exits non-zero
	// over, and doctor saying warn where status says fail would leave the two
	// describing different hosts.
	if len(check.Secrets.NotRedactable) > 0 {
		report.addf("refused refs", StatusFailed, "%d ref(s) cannot be "+
			"redacted, so they are never injected and never redacted: %s. Fix each with "+
			"`sudo faramir vault edit`; the reason beside each says what to change",
			len(check.Secrets.NotRedactable), check.RefusedRefs())
		explained = true
	}
	// A ref two managed files both defined. Reported beside the refused refs because
	// the consequence is the same one: a value this host manages that is injected
	// by nothing and covered by nothing, so a command printing it prints it. The
	// difference is that a short value is knowingly outside the redactor and this
	// one is not, which is why it is named rather than left to a daemon log line.
	if len(check.Secrets.ShadowedRefs) > 0 {
		report.addf("shadowed refs", StatusFailed, "%d ref(s) are defined with "+
			"different values in more than one managed file, so one of the values is in "+
			"no redactor and a command that prints it prints it in the clear: %s. Remove "+
			"the ref from one file with `sudo faramir vault edit`",
			len(check.Secrets.ShadowedRefs), brokercheck.RefsWithReasons(check.Secrets.ShadowedRefs))
		explained = true
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
		report.addf("linked refs", StatusFailed, "%s did not load, so those "+
			"refs answer nothing while every other ref is served: %s. Fix each file, then "+
			"`sudo systemctl restart faramir-broker`: the broker fingerprints a linked "+
			"file by mtime and size, so a repair that changes neither is not noticed",
			brokercheck.LinkEntries(len(check.Secrets.DegradedLinks)), check.DegradedRefs())
		explained = true
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
	if check.Serves() {
		return servesValues
	}
	return servesNothing
}
