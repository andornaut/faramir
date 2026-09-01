// Package enroll enrols one project tree: the group and modes that let a
// brokered command run there, and the agent configuration that makes the broker
// worth using.
//
// Separate from internal/install, which provisions the host. The split is what
// each run is about rather than what it writes: provisioning happens once per
// machine and this once per tree, which is also what makes the working
// directory safe to default to here and unsafe there. The two share only the
// recording, in internal/steps.
//
// internal/install depends on this rather than the other way round: every
// `faramir init` re-asserts the trees already enrolled, and the refusals a tree
// is held to have to be the same ones on both paths.
package enroll

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/steps"
	"github.com/andornaut/faramir/internal/version"
)

// Options is one enrolment.
type Options struct {
	// Dir is the tree to enrol. Defaults to the working directory.
	Dir string
	// Operator owns the tree and keeps owning it; this grants group access for the
	// executor's uid.
	AgentUser string
	// ConfigDir is where the client group is learned. A flag could disagree with
	// what the sockets admit, leaving a tree the executor cannot enter.
	ConfigDir string
	// ClientGroup overrides the group the config names, for a tree shared with a
	// group other than the one this host's socket admits.
	//
	// It overrides one value and does not stand in for the config, which still
	// has to load: an enrolment writes this install's deny rules into the tree,
	// and the linked and blocked paths among them are only in that file. This
	// runs as root and the config is 0644, so a load fails only because faramir
	// was never installed here, the config is elsewhere, or the path given is
	// wrong, each of which is an error naming its own fix.
	ClientGroup string
	// Agents names which coding agents to enrol. Empty means agentcfg.Auto:
	// whichever agents this tree already carries configuration for. A name
	// enrols that agent whether or not it is there, and composes with auto.
	Agents []string
	DryRun bool
	Log    func(string)
}

// Report is one enrolment's outcome.
type Report struct {
	steps.Report

	Version     string `json:"version"`
	Dir         string `json:"dir"`
	ClientGroup string `json:"group"`
	DryRun      bool   `json:"dry_run,omitempty"`
}

// Tree enrols one project tree: the group and modes that let a brokered command
// run there, and the agent configuration that makes the broker worth using.
func Tree(opts Options) (Report, error) {
	if opts.Dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return Report{}, err
		}
		opts.Dir = cwd
	}
	named := opts.Dir
	info, err := os.Stat(named)
	if err != nil || !info.IsDir() {
		return Report{}, fmt.Errorf("no directory at %s", named)
	}
	// Symlinks out before anything is decided: sharing follows a link with its
	// chmod and chown and not with its walk. See sharetree.Resolve.
	dir, err := sharetree.Resolve(named)
	if err != nil {
		return Report{}, fmt.Errorf("resolving %s: %w", named, err)
	}
	opts.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = hostlayout.DefaultConfigDir
	}

	// uid and gid keep rather than 0 until preflight resolves them, so a write
	// that lands before that leaves ownership as it is rather than handing the
	// operator's file to root.
	run := &project{opts: opts, fs: hostfs.FS{DryRun: opts.DryRun}, uid: hostfs.Keep, gid: hostfs.Keep}
	run.report = Report{Version: version.Version, Dir: dir, DryRun: opts.DryRun}
	run.report.LogTo(opts.Log)
	// The tree being changed is somewhere other than where it was named. Made
	// absolute and cleaned first: `.`, a relative path and a trailing slash all
	// name the tree in front of the operator, and saying that one of them
	// resolves to the tree being enrolled tells them nothing. A symlink is what
	// this is for, where the enrolment lands on a directory they did not type.
	if abs, err := filepath.Abs(named); err != nil || filepath.Clean(abs) != dir {
		run.warnf("%s resolves to %s, which is the tree being enrolled", named, dir)
	}
	if err := run.preflight(); err != nil {
		return run.report, err
	}
	for _, step := range run.steps() {
		if err := step.Run(); err != nil {
			// Named, as `init` names its own: a run that stops partway has applied
			// everything before it and nothing after, and the first step here is the
			// one that cannot be undone.
			return run.report, fmt.Errorf("%s: %w", step.Name, err)
		}
	}
	// Recorded last: `doctor` reads this rather than guessing which agents are in
	// use from what is in a home.
	//
	// Fatal, though the enrolment itself succeeded. A tree that is enrolled and
	// unrecorded is one `faramir init` stops maintaining and `doctor` stops
	// checking, and it looks like every other enrolled tree from the outside: an
	// exit code is the only thing that tells whoever ran this that the tree needs
	// enrolling again.
	if !opts.DryRun {
		names := make([]string, 0, len(run.targets))
		for _, target := range run.targets {
			names = append(names, target.Name)
		}
		if err := agentcfg.RecordEnrolment(opts.ConfigDir, agentcfg.EnrolledTree{
			Dir: dir, AgentUser: opts.AgentUser, Agents: names,
		}); err != nil {
			return run.report, fmt.Errorf("%s is enrolled, and recording it in %s "+
				"failed, so `faramir init` will not maintain it and `faramir doctor` "+
				"will not check it: %w\nRun this again once whatever else is writing "+
				"that file has finished", dir, agentcfg.EnrolledPath(opts.ConfigDir), err)
		}
	}
	return run.report, nil
}

// steps is the order an enrolment is applied in. shareTree walks the tree
// chowning and chmodding every file in it and nothing undoes that, so
// everything else runs after the irreversible part and every refusal belongs in
// preflight. The share goes first because what follows writes into the tree,
// and a file written before the walk is one the walk then regroups.
func (p *project) steps() []steps.Named {
	return []steps.Named{
		{Name: "share tree", Run: p.shareTree},
		{Name: steps.LabelAgentConfig, Run: p.agentConfig},
		{Name: "instructions", Run: p.instructions},
	}
}

type project struct {
	opts   Options
	fs     hostfs.FS
	report Report
	uid    int
	gid    int
	// allowSudo is whether this host was installed with --allow-sudo, read off
	// the config beside the client group, and decides one paragraph of the
	// credentials section. False for an enrolment that named --client-group and
	// so never read a config: the section then says nothing about escalations,
	// which is the safe direction.
	allowSudo bool
	// agentHome is the operator's own home, which auto consults for an agent that
	// keeps nothing beside a project. Empty where the account does not resolve,
	// which leaves such an agent to be named rather than found.
	agentHome string
	// Resolved before any step runs, so an unknown name stops the run before the
	// tree's ownership changes.
	targets []*agentcfg.Target
}

// step, skip and warnf are the report's, forwarded so a step here spells them
// the way a step in `init` does.
func (p *project) step(name string, changed bool, detail string) {
	p.report.Record(name, changed, detail)
}

func (p *project) skip(name, why string) { p.report.Skip(name, why) }

func (p *project) warnf(format string, args ...any) {
	p.report.Warnf(format, args...)
}
