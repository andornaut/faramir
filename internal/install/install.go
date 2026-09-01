// Package install provisions a host: the accounts, the directories, the age
// key, the binaries, the systemd units, the sudo arrangement, the coding
// agents' account-wide configuration, and the linked and blocked paths an
// operator declares afterwards.
//
// Enrolling one tree is internal/enrol's, that being once per tree where this
// is once per machine. This depends on it: every run re-asserts the trees
// already enrolled, and the refusals a tree is held to have to be the same ones
// on both paths. The recording both keep is internal/steps.
//
// The entry editors are here rather than beside the config they write, because
// adding a link or a blocked path applies a subset of these same steps: the
// grant, the deny rules and the trees they have to reach.
//
// It writes. Saying whether what landed works is internal/doctor's, and the two
// are siblings: neither imports the other, and both build a hostlayout.Layout
// first, so a check compares against the values the write came from rather than
// against a second reading of them.
//
// What every step renders from is that Layout, and what every step writes
// through is a hostfs.FS, which reports whether it changed anything so a
// configuration manager need not stat the host before and after.
package install

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/steps"
	"github.com/andornaut/faramir/internal/version"
)

// Report is the whole run.
type Report struct {
	steps.Report

	Version string `json:"version"`
	DryRun  bool   `json:"dry_run,omitempty"`
	// BrokerPublicKey has to be in authorized_keys on every managed host.
	// Reported every run, not only when it was generated.
	BrokerPublicKey string `json:"broker_public_key,omitempty"`
	// AgeRecipients is who can decrypt the managed files: what .sops.yaml lists,
	// read back on every run but the one that writes the file, which reports what
	// it just sealed the store to. Empty when the file could not be read.
	AgeRecipients []string `json:"age_recipients,omitempty"`
}

// recordConfigDigest remembers config.toml as it stands, for a run that is
// about to write back entries it has just read out of it.
func recordConfigDigest(opts *Options, configFile string) error {
	opts.configRead = true
	body, err := os.ReadFile(configFile)
	if errors.Is(err, os.ErrNotExist) {
		// Nothing there. The digest stays nil, which with configRead set is an
		// expectation of its own: a file that appears before the write is another
		// run that got there first.
		return nil
	}
	if err != nil {
		return err
	}
	sum := sha256.Sum256(body)
	opts.configDigest = sum[:]
	return nil
}

type runner struct {
	opts   Options
	layout hostlayout.Layout
	fs     hostfs.FS
	report Report

	// The directory the running faramir came out of, so the binary that
	// provisions the host is the one that lands on it.
	binaries string

	// What the validation step established, not what it was asked to check: it
	// skips under DryRun and without systemd.
	brokerLoadedRefs int
	brokerChecked    bool

	// The key the broker will load, set once it is on disk with the ownership the
	// broker needs. Empty under a dry run, so the validation step knows not to
	// ask a broker that was never given one.
	sshKey string

	// The agents this run configures, resolved in stepPreconditions so the
	// question asked there and the files written later are about the same set.
	agentTargets []*agentcfg.Target

	// The keeper's own age recipient, empty when it could not be read. A
	// .sops.yaml written without it encrypts every later value to everyone except
	// the account that has to decrypt them.
	keeperRecipient string

	// What the running daemons would not otherwise pick up: none re-reads its
	// config or reloads its binary, and nothing else is worth killing the
	// commands in flight for.
	needsRestart   bool
	restartReasons []string

	// What this run took from the install it found rather than from a flag, as
	// "--flag value".
	adopted []string

	// Resolved after the accounts step; keep when the account does not exist,
	// which only happens under DryRun.
	operatorUID  int
	operatorGID  int
	operatorHome string
	brokerUID    int
	keeperUID    int
	execUID      int
	execGID      int
	secretsGID   int
	brokerGID    int
	keeperGID    int
}

// Run provisions the host. Idempotent: a second run with the same options
// changes nothing and reports so.
func Run(opts Options) (Report, error) {
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, err
	}
	return run.apply(run.steps())
}

// newRunner builds what every run shares: adoption, defaults, the layout, and
// the refusals that must happen before anything is written.
func newRunner(opts Options) (*runner, error) {
	// Before the defaults: adoption is what keeps a flag left out from reverting
	// the install, and applyDefaults cannot tell an omitted flag from one that
	// named the compiled-in value.
	adopted, err := opts.adoptInstalled()
	if err != nil {
		return nil, err
	}
	opts.applyDefaults()
	layout, err := opts.layout()
	if err != nil {
		return nil, err
	}
	run := &runner{
		opts:    opts,
		layout:  layout,
		fs:      hostfs.FS{DryRun: opts.DryRun},
		report:  Report{Version: version.Version, DryRun: opts.DryRun},
		adopted: adopted,
	}
	run.report.LogTo(opts.Log)
	if self, err := os.Executable(); err == nil {
		run.binaries = filepath.Dir(self)
	}
	if err := run.preflight(); err != nil {
		return nil, err
	}
	return run, nil
}

// apply runs the steps given, in order.
func (r *runner) apply(steps []steps.Named) (Report, error) {
	for _, step := range steps {
		if err := step.Run(); err != nil {
			// Named, because a run that stops partway has applied everything before
			// it and nothing after. The steps that hand a file to an account are all
			// after stepPreconditions, so a refusal there has changed no ownership.
			return r.report, fmt.Errorf("%s: %w", step.Name, err)
		}
	}
	return r.report, nil
}

// steps is the order the install is applied in, which is itself a boundary:
// everything before stepPreconditions adds accounts and groups and can be
// repeated, everything after hands existing files to them and cannot be undone
// by running init again. A refusal that a later step could raise and
// stepPreconditions can ask belongs in stepPreconditions.
func (r *runner) steps() []steps.Named {
	return []steps.Named{
		{Name: "adopted", Run: r.stepAdopted},
		{Name: "accounts", Run: r.stepAccounts},
		{Name: steps.LabelResolveIDs, Run: r.resolveIDs},
		{Name: steps.LabelPreconditions, Run: r.stepPreconditions},
		{Name: "directories", Run: r.stepDirectories},
		{Name: "age key", Run: r.stepAgeKey},
		{Name: "sops config", Run: r.stepSopsConfig},
		{Name: "binaries", Run: r.stepBinaries},
		{Name: steps.LabelConfig, Run: r.stepConfig},
		// After the config, which is where [ssh] key is recorded, and before any
		// daemon starts: a key the broker cannot read leaves the agent holding
		// nothing.
		{Name: "ssh key", Run: r.stepSSHKey},
		// The other half of reaching a managed host: the key authenticates to it,
		// these say which host answering is that host.
		{Name: "known hosts", Run: r.stepKnownHosts},
		// After the config, which renders [sudo] from the same layout, and
		// before anything restarts a daemon: a broker that came up without the PAM
		// service and the sudoers entry in place would refuse every escalation
		// until the next activation.
		{Name: "sudo grant", Run: r.stepSudoGrant},
		// Before the units are written: it grants the traversal that lets a service
		// uid reach a config under the agent account's home.
		{Name: "reachable", Run: r.stepReachable},
		// After the step above, this granting traversal down to a file in the same
		// home: the two must not race to regroup the directories they share.
		{Name: "linked files", Run: r.stepLinkAccess},
		{Name: "units", Run: r.stepUnits},
		{Name: "systemd", Run: r.stepSystemd},
		{Name: steps.LabelAgentConfig, Run: r.stepAgentConfig},
		// The same rules in every tree already enrolled, so a re-run restores what
		// a tree dropped as well as what the home did. docs/configuration.md says
		// init re-asserts every rule on each run, and until this step that was
		// true of the home alone.
		{Name: steps.LabelEnrolledTrees, Run: r.stepEnrolledTrees},
		{Name: "validate", Run: r.stepValidate},
	}
}

// step, skip and warnf are the report's, forwarded so every caller in this
// package spells them the same way.
func (r *runner) step(name string, changed bool, detail string) {
	r.report.Record(name, changed, detail)
}

func (r *runner) skip(name, why string) { r.report.Skip(name, why) }

// reportPresence is the dry-run answer for a step that only asks whether a file
// is there. Nothing is opened: several are key material.
func (r *runner) reportPresence(name, path, wouldCreate string) {
	present, known := hostfs.Probe(path)
	switch {
	case !known:
		r.skip(name, "cannot tell whether "+path+" is there without root")
	case present:
		r.step(name, false, "keeping "+path)
	default:
		r.step(name, true, wouldCreate+" "+path)
	}
}

// warnLongSudoTimeout says when a question will be held to less than the value
// this run names. The loader settles the relation -- a question may not outlast
// the command waiting inside sudo for it -- and settles it quietly, so this is
// where an operator hears about it: the two numbers are named together here and
// nowhere else, and the file keeps what the flag asked for while the daemons
// hold to the smaller of the two.
//
// A warning rather than a refusal, for the reason the loader clamps rather than
// refusing: each value is legal on its own, and a host that lowered
// max_timeout_sec should not be left unable to install.
func (r *runner) warnLongSudoTimeout() {
	if !r.opts.AllowSudo || r.opts.SudoTimeoutSec <= r.opts.CommandMaxTimeoutSec {
		return
	}
	r.warnf("--sudo-timeout %ds is longer than the %ds a brokered command may run, "+
		"so a question is held to %ds. Raise --command-max-timeout to allow longer",
		r.opts.SudoTimeoutSec, r.opts.CommandMaxTimeoutSec, r.opts.CommandMaxTimeoutSec)
}

// restartFor records that a running daemon is now behind what is installed.
func (r *runner) restartFor(what string) {
	r.needsRestart = true
	if !slices.Contains(r.restartReasons, what) {
		r.restartReasons = append(r.restartReasons, what)
	}
}

func (r *runner) warnf(format string, args ...any) {
	r.report.Warnf(format, args...)
}
