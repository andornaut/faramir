package install

// Enrolling one project, as against provisioning the host. `init` runs once
// per machine; this runs once per tree. That is also what makes the working
// directory safe to default to here and unsafe there.

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sharetree"
	"github.com/andornaut/faramir/internal/version"
)

// agentInstructionFiles are the names an agent reads, most specific first; the
// first is created when there is none.
var agentInstructionFiles = []string{"AGENTS.md", "CLAUDE.md"}

// ProjectOptions is one enrolment.
type ProjectOptions struct {
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
	// Agents names which coding agents to enrol. Empty means AgentAuto:
	// whichever agents this tree already carries configuration for. A name
	// enrols that agent whether or not it is there, and composes with auto.
	Agents []string
	DryRun bool
	Log    func(string)
}

// ProjectReport is one enrolment's outcome.
type ProjectReport struct {
	runReport

	Version     string `json:"version"`
	Dir         string `json:"dir"`
	ClientGroup string `json:"group"`
	DryRun      bool   `json:"dry_run,omitempty"`
}

// Project enrols one tree: the group and modes that let a brokered command run
// there, and the agent configuration that makes the broker worth using.
func Project(opts ProjectOptions) (ProjectReport, error) {
	if opts.Dir == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return ProjectReport{}, err
		}
		opts.Dir = cwd
	}
	named := opts.Dir
	info, err := os.Stat(named)
	if err != nil || !info.IsDir() {
		return ProjectReport{}, fmt.Errorf("no directory at %s", named)
	}
	// Symlinks out before anything is decided: sharing follows a link with its
	// chmod and chown and not with its walk. See sharetree.Resolve.
	dir, err := sharetree.Resolve(named)
	if err != nil {
		return ProjectReport{}, fmt.Errorf("resolving %s: %w", named, err)
	}
	opts.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}

	// uid and gid keep rather than 0 until preflight resolves them, so a write
	// that lands before that leaves ownership as it is rather than handing the
	// operator's file to root.
	run := &project{opts: opts, fs: fsys{dryRun: opts.DryRun}, uid: keep, gid: keep}
	run.report = ProjectReport{
		Version: version.Version,
		Dir:     dir,
		DryRun:  opts.DryRun,
		log:     opts.Log,
	}
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
		if err := step.run(); err != nil {
			// Named, as `init` names its own: a run that stops partway has applied
			// everything before it and nothing after, and the first step here is the
			// one that cannot be undone.
			return run.report, fmt.Errorf("%s: %w", step.name, err)
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
			names = append(names, target.name)
		}
		if err := recordEnrolment(opts.ConfigDir, EnrolledTree{
			Dir: dir, AgentUser: opts.AgentUser, Agents: names,
		}); err != nil {
			return run.report, fmt.Errorf("%s is enrolled, and recording it in %s "+
				"failed, so `faramir init` will not maintain it and `faramir doctor` "+
				"will not check it: %w\nRun this again once whatever else is writing "+
				"that file has finished", dir, enrolledPath(opts.ConfigDir), err)
		}
	}
	return run.report, nil
}

// steps is the order an enrolment is applied in. shareTree walks the tree
// chowning and chmodding every file in it and nothing undoes that, so
// everything else runs after the irreversible part and every refusal belongs in
// preflight. The share goes first because what follows writes into the tree,
// and a file written before the walk is one the walk then regroups.
func (p *project) steps() []namedStep {
	return []namedStep{
		{"share tree", p.shareTree},
		{labelAgentConfig, p.agentConfig},
		{"instructions", p.instructions},
	}
}

// preflight is every refusal this command can make, asked before the walk that
// cannot be undone: a check that fails at its own step leaves a half-enrolled
// tree.
func (p *project) preflight() error {
	if p.opts.AgentUser == "" || p.opts.AgentUser == "root" {
		return fmt.Errorf("no account is named for %s: run through sudo so SUDO_USER "+
			"carries it, or record the account with `faramir init --agent-user`. Root "+
			"here would chown a checkout away from its owner", p.opts.Dir)
	}
	if os.Geteuid() != 0 && !p.opts.DryRun {
		return errors.New("faramir init-project must run as root: it " +
			"changes group ownership and modes on the tree it enrols")
	}
	if err := refuseOversharing(p.opts.Dir, p.opts.AgentUser); err != nil {
		return err
	}
	if err := refuseInstallDirs(p.opts.Dir, p.opts.ConfigDir); err != nil {
		return err
	}
	// auto looks at the tree, enrolling costing something here. Resolved before
	// anything is written, so an unknown name stops the run before the tree's
	// ownership changes.
	// Not fatal: an account that does not resolve fails later with a message
	// about the account, and auto losing one agent is not the error to report
	// here.
	p.agentHome, _ = agentHomeFor(p.opts.AgentUser)
	targets, err := resolveAgents(p.opts.Agents, scopeTree, p.opts.Dir, p.agentHome)
	if err != nil {
		return err
	}
	p.targets = targets
	if err := p.resolveGroup(); err != nil {
		return err
	}
	if err := p.resolveIDs(); err != nil {
		return err
	}
	if err := p.refuseUnreachable(); err != nil {
		return err
	}
	p.warnMissingBinary(filepath.Join(DefaultBinDir, "faramir"))
	if err := p.refuseUnwritableFiles(); err != nil {
		return err
	}
	return p.refuseUnparsableAgentConfig()
}

// refuseUnparsableAgentConfig asks, before the share, the other question every
// merge into this tree will ask. faramir writes its keys into the agent's own
// file rather than replacing it, so a file that does not parse is refused, and
// finding that out at the write is too late: the share has already handed the
// client group read and write on every file in the tree, and the run then stops
// without registering the hook that was the point of it, leaving a tree open
// and guarded by nothing.
//
// Only a parse failure. A file that cannot be read or is not the operator's is
// refuseUnwritableFiles's to name, and saying it twice would put one problem in
// front of the operator under two headings.
func (p *project) refuseUnparsableAgentConfig() error {
	var refused []string
	for _, target := range p.targets {
		for _, file := range target.files {
			if !file.merge {
				continue
			}
			path := filepath.Join(p.opts.Dir, file.path)
			spot, err := p.fs.editedFile(path, p.uid, p.opts.Dir)
			if err != nil {
				spot.close()
				continue
			}
			data, readErr := spot.read()
			spot.close()
			if readErr != nil || len(bytes.TrimSpace(data)) == 0 {
				continue
			}
			var into any
			if err := json.Unmarshal(data, &into); err != nil {
				refused = append(refused, fmt.Sprintf(
					"%s: parsing the file already there: %v. faramir merges its keys "+
						"into this file rather than replacing it, so nothing was written "+
						"and the tree was not shared", path, err))
			}
		}
	}
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// refuseUnreachable stops an enrolment that would share a tree nothing can
// reach. A home is 0700, so every directory between it and the tree has to let
// the client group through, and group execute on the tree grants nothing while
// a directory above it refuses the traversal.
//
// Reported rather than opened: the enrolled tree is the one place faramir
// changes ownership and modes, and those directories are outside it. Whoever
// manages the host's permissions sets them.
func (p *project) refuseUnreachable() error {
	if p.opts.DryRun {
		return nil
	}
	blocked, err := sharetree.Traversable(sharetree.Options{
		Dir: p.opts.Dir, Operator: p.opts.AgentUser, Group: p.report.ClientGroup,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	if len(blocked) == 0 {
		return nil
	}
	return fmt.Errorf("%s cannot enter %s, so %s would be shared and unreachable. "+
		"faramir changes ownership and modes on the tree it enrols and nowhere "+
		"else; open them and run this again:\n%s",
		p.report.ClientGroup, sharetree.Describe(blocked), p.opts.Dir,
		sharetree.Fix(blocked, p.report.ClientGroup))
}

// refuseUnwritableFiles asks, before the share, the question every write into
// this tree will ask: the share chowns and chmods every file in the tree and
// nothing undoes it, so finding out afterwards that a settings file is not the
// operator's is too late.
func (p *project) refuseUnwritableFiles() error {
	paths, err := p.relativeInstructions()
	if err != nil {
		return err
	}
	for _, target := range p.targets {
		paths = append(paths, editedPaths(target, true, "")...)
	}
	refused := refuseUnwritable(p.fs, p.opts.Dir, p.uid, p.opts.Dir, paths)
	// The mode the share settles on, so what this asks is what the write asks.
	refused = append(refused, refuseUnenterableDirs(
		p.opts.Dir, 0o2770|os.ModeSetgid, p.uid, p.gid, paths)...)
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// resolveIDs turns the operator and the client group into ids, before anything
// is written with them. A dry run is allowed to fail here and carry on, so a
// tree can be asked about on a host that has not been provisioned yet: the ids
// stay keep, and nothing a dry run reaches writes.
func (p *project) resolveIDs() error {
	uid, err := lookupUser(p.opts.AgentUser)
	if err != nil {
		if p.opts.DryRun {
			return nil
		}
		return err
	}
	gid, err := lookupGroup(p.report.ClientGroup)
	if err != nil {
		if p.opts.DryRun {
			return nil
		}
		return err
	}
	p.uid, p.gid = uid, gid
	return nil
}

// warnMissingBinary says so when the binary every agent's hook and plugin is
// about to be pointed at is not installed. Warned rather than refused:
// --client-group enrols a tree for an install that need not be on this machine.
// On the host that runs it the hook and the plugins fail closed, refusing every
// command in the project rather than running one unredacted.
func (p *project) warnMissingBinary(binary string) {
	if exists(binary) {
		return
	}
	p.warnf("%s is not installed, and it is what every hook and plugin written here execs. They "+
		"fail closed, so the agents would refuse every command in %s rather than run one "+
		"unredacted. Run `sudo faramir init` on the host that runs this tree", binary, p.opts.Dir)
}

// refuseOversharing stops an enrolment that would share far more than a
// project. Sharing grants the client group read and write on every file in the
// tree, and faramir-exec is in that group: for a home that is ~/.ssh,
// ~/.config/sops/age/keys.txt, and group write on the shell configuration that
// decides what the operator's next login runs. Blocked rather than warned
// about, the walk not being reversible.
func refuseOversharing(dir, operator string) error {
	tooBig := func(what string) error {
		return fmt.Errorf("refusing to enrol %s: it is %s. Enrolling gives the client group read and write "+
			"on every file in it. Name the project directory instead", dir, what)
	}
	switch dir {
	case "/":
		return tooBig("the root of the filesystem")
	case "/home":
		return tooBig("every home on this host")
	}
	if slices.Contains(systemRoots, dir) {
		return tooBig("a system directory rather than a project")
	}
	if home := homeOf(dir); home == dir {
		return tooBig("a home directory")
	}
	// The account's own home as passwd records it, which catches one outside
	// /home and /root. Resolved, because dir is. An unknown account fails later
	// in shareTree, with the error that names it.
	if entry, err := user.Lookup(operator); err == nil && entry.HomeDir != "" {
		home, err := sharetree.Resolve(entry.HomeDir)
		if err != nil {
			home = filepath.Clean(entry.HomeDir)
		}
		if home == dir {
			return tooBig(operator + "'s home directory")
		}
		if encloses(dir, home) {
			return tooBig("above " + operator + "'s home directory")
		}
	}
	return nil
}

// systemRoots are the directories a walk must not be pointed at. Sharing chowns
// the directory to the operator, chmods it 2770 and applies g+rwX to everything
// under it, so one of these regrouped is a host repaired from outside faramir
// or not at all.
//
// Named rather than derived from "outside /home": a checkout on shared storage
// is a tree an operator may legitimately enrol, needing the drop-in extending
// ReadWritePaths= that shareTree warns about. /root is absent, homeOf naming it
// as the home it is.
//
// The merged-/usr targets are listed with the links that point at them: the
// directory reaching this has been through sharetree.Resolve, so /bin arrives
// as /usr/bin on most hosts and as itself on the rest.
var systemRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/opt", "/proc", "/run", "/sbin", "/snap", "/srv", "/sys", "/tmp",
	"/usr", "/var",
	"/usr/bin", "/usr/include", "/usr/lib", "/usr/lib32", "/usr/lib64",
	"/usr/libx32", "/usr/local", "/usr/sbin", "/usr/share", "/var/tmp",
}

// refuseInstallDirs stops an enrolment that would walk faramir's own
// directories. The age key is 0400 and keeper-owned, and sharing ORs group read
// and write onto every file in the tree and regroups it: one walk over the
// config directory hands the client group, which faramir-exec is in, the key
// that decrypts every managed file.
//
// Both directions. A tree above one of these reaches it through the walk, and a
// tree inside one is part of it. systemRoots names /etc and its kind; this
// names what an install puts inside them, and reaches a --config-dir moved
// under a home, which no fixed list can name.
func refuseInstallDirs(dir, configDir string) error {
	// BinDir with them: it holds the binary every hook and plugin execs, and
	// group write there is a brokered command replacing what the agent runs.
	//
	// ruleLayout rather than the config directory alone: it reads the service
	// accounts off the installed units, so a host that renamed one has the
	// directory it moved to refused rather than the one it left.
	dirs := append(installDirs(ruleLayout(configDir)), DefaultBinDir)
	for _, installed := range dirs {
		installed = filepath.Clean(installed)
		holds := encloses(dir, installed)
		if !holds && !encloses(installed, dir) {
			continue
		}
		relation := "holds"
		switch {
		case installed == dir:
			relation = "is"
		case !holds:
			relation = "is inside"
		}
		return fmt.Errorf("refusing to enrol %s: it %s %s, which is faramir's own. Enrolling gives the "+
			"client group read and write on every file in it, and faramir-exec is in that "+
			"group. Name the project directory instead", dir, relation, installed)
	}
	return nil
}

// encloses compares path elements, so /home/andornaut2 is not inside
// /home/andornaut.
func encloses(parent, child string) bool {
	rel, err := filepath.Rel(parent, child)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

type project struct {
	opts   ProjectOptions
	fs     fsys
	report ProjectReport
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
	targets []*agentTarget
}

// step, skip and warnf are the report's, forwarded so a step here spells them
// the way a step in `init` does.
func (p *project) step(name string, changed bool, detail string) {
	p.report.step(name, changed, detail)
}

func (p *project) skip(name, why string) { p.report.skip(name, why) }

func (p *project) warnf(format string, args ...any) {
	p.report.warnf(format, args...)
}

// resolveGroup reads the shared group out of the installed config.
// allowed_group is what the broker socket admits, so it is the only value that
// makes a shared tree usable. The sudo grant is read from the same load,
// [sudo] exec_user being the switch for the whole arrangement.
//
// The config has to load, --client-group or not. It is where the linked and
// blocked paths are, and those are rules an enrolment writes into the tree: a
// tree enrolled without them carries a deny list that names the built-in paths
// and not the credential file this install added, which reads exactly like one
// that covers everything. --client-group overrides the group it found, and is
// not a way to enrol against no config at all.
func (p *project) resolveGroup() error {
	configFile := filepath.Join(p.opts.ConfigDir, "config.toml")
	cfg, err := config.Load(configFile)
	if err != nil {
		// A dry run writes nothing, so it has no incomplete rules to prevent, and
		// asking about a tree from a host that has not been provisioned yet is what
		// it is for. The same latitude resolveIDs takes.
		if p.opts.DryRun {
			p.warnf("cannot read %s (%v), so this reports on the tree alone: the "+
				"group it would be shared with and the deny rules an enrolment would "+
				"write are both in that file", configFile, err)
			p.report.ClientGroup = p.opts.ClientGroup
			return nil
		}
		return fmt.Errorf("cannot read %s: %w\nAn enrolment writes this install's deny rules into the tree, "+
			"and the linked and blocked paths are in that file. Run `faramir init` first, or "+
			"set FARAMIR_CONFIG if the config is elsewhere", configFile, err)
	}
	// The grant is this host's, and says nothing about a tree shared with a group
	// this host's socket does not admit: that names another install, whose
	// escalation arrangement is its own.
	if p.opts.ClientGroup == "" || cfg.Server.AllowedGroup == p.opts.ClientGroup {
		p.allowSudo = cfg.Sudo.ExecUser != ""
	}
	if p.opts.ClientGroup != "" {
		p.report.ClientGroup = p.opts.ClientGroup
		return nil
	}
	if cfg.Server.AllowedGroup == "" {
		return fmt.Errorf("%s admits no group, so a shared tree would reach nothing. "+
			"Run `faramir init --client-group NAME`", configFile)
	}
	p.report.ClientGroup = cfg.Server.AllowedGroup
	return nil
}

// warnMissingAccountRules says so when an agent's account-wide deny rules are
// not in the agent account's home. Enrolling a tree writes the per-project
// hook; the rules that hold wherever the agent works are written by `faramir
// init --agent`.
// warnUnexpressiblePatterns names the declared patterns this agent's rule file
// cannot carry, for the one agent whose matcher has no spelling for some of
// them. Said rather than dropped silently: a file short of what the config
// declares reads exactly like one that carries all of it, and the operator is
// the only one who can decide whether to name the path instead.
//
// The command guard still refuses these, reading the same list, so what is lost
// is the file tools rather than the whole rule.
func warnUnexpressiblePatterns(p *project, target *agentTarget) {
	if target.familyName() != antigravityFamily {
		return
	}
	missing := agyUnexpressible(ruleLayout(p.opts.ConfigDir))
	if len(missing) == 0 {
		return
	}
	p.warnf("%s: %v cannot be written as a rule this agent matches, its patterns "+
		"taking one leading wildcard and no separator after it. Its file tools are "+
		"not refused those; `cat` and the rest still are. Name the path rather than "+
		"the pattern to cover both", target.name, missing)
}

func warnMissingAccountRules(p *project, target *agentTarget) {
	if len(target.accountFiles) == 0 {
		return
	}
	home, err := agentHomeFor(p.opts.AgentUser)
	if err != nil || home == "" {
		return
	}
	var missing []string
	for _, file := range target.accountFiles {
		if !exists(filepath.Join(home, file.path)) {
			missing = append(missing, "~/"+file.path)
		}
	}
	if len(missing) == 0 {
		return
	}
	// What those rules cover is what this install writes, plus whatever a
	// [[secret.link]] or [[secret.block]] entry names: see protectedpaths.go,
	// which renders the same set into the bash deny list. Named that way rather
	// than by example, a rule for a path faramir did not choose being the thing
	// that design refuses to compile in.
	p.warnf("%s's deny rules are not in the agent account's home (%s), so its file tools are "+
		"refused nothing this install protects, and no uid boundary refuses them either. "+
		"Run `sudo faramir init --agent %s`",
		target.name, strings.Join(missing, ", "), target.name)
}

// agentHomeFor is the account's home directory.
func agentHomeFor(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	entry, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return entry.HomeDir, nil
}

// pluginData is what an agent plugin's template is rendered against: the binary
// it execs, which agent it speaks to, and the path it is written to. Not the
// install Layout, none of the last two being install-wide.
type pluginData struct {
	BinDir string
	Agent  string
	// Family is the tree enrolment this file belongs to, and what a registration
	// shared by two agents names itself. See agentTarget.family.
	Family        string
	Path          string
	DefaultExport bool
	// Layout is what the rule renderers take: this install's own directories and
	// the paths its config names as linked or refused. Built from the enrolment's
	// --config-dir, so a store moved into a home is the one refused rather than
	// the default, and built by ruleLayout so what an enrolment writes is what
	// `doctor` re-renders to compare it with.
	Layout Layout
}

// assetFor is one agent file's contents, rendered whatever the asset is named.
// It is how the plugins and the hook registrations get the installed binary's
// path compiled in rather than reading it from an environment the host
// controls.
func assetFor(target *agentTarget, file agentFile, configDir string) ([]byte, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return renderData(file.asset, pluginData{
		// The compiled path, as uninstall and reload resolve it: a post-install
		// command reads the binary where the install put it.
		BinDir:        DefaultBinDir,
		Agent:         target.name,
		Family:        target.familyName(),
		Path:          file.path,
		DefaultExport: file.defaultExport,
		Layout:        ruleLayout(configDir),
	})
}

// keepModes is every path this enrolment writes, so sharing does not widen a
// mode this command then narrows again. Relative to the tree, which is how
// sharetree matches them.
func (p *project) keepModes() []string {
	keep := []string{}
	if rel, err := p.relativeInstructions(); err == nil {
		keep = append(keep, rel...)
	}
	// p.targets, not a second resolution: auto reads the tree, and this runs after
	// files have been written into it.
	for _, target := range p.targets {
		for _, file := range target.files {
			keep = append(keep, file.path)
		}
	}
	return keep
}

func (p *project) shareTree() error {
	if p.opts.DryRun {
		p.step("share tree", false, fmt.Sprintf("%s with group %s",
			p.opts.Dir, p.report.ClientGroup))
		return nil
	}
	result, err := sharetree.Share(sharetree.Options{
		Dir: p.opts.Dir, Operator: p.opts.AgentUser, Group: p.report.ClientGroup,
		Keep: p.keepModes(),
	})
	if err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	// The executor runs under ProtectSystem=strict with /home as its only
	// writable tree, so a tree outside it takes the group and then refuses every
	// write with EROFS.
	if homeOf(p.opts.Dir) == "" {
		p.warnf("%s is outside /home, which is the only tree faramir-exec may write: a brokered "+
			"command enters it and gets EROFS on every write. Add a drop-in extending "+
			"ReadWritePaths= on faramir-exec.service",
			p.opts.Dir)
	}
	// What it altered, not whether it ran: the first run rewrites the ownership
	// and mode of every file in the tree, and reporting that as no change would
	// tell anything reading Changed that a regrouped tree was left alone.
	//
	// What was held back is named alongside the count, this being the one command
	// that changes a path it does not own: a bare "1200 paths regrouped" does not
	// say that the agent's own files kept their mode and their directories were
	// closed to unlink by anyone but their owner.
	detail := detailWithCount(fmt.Sprintf("%s with group %s, setgid, "+
		"owner %s", p.opts.Dir, p.report.ClientGroup, p.opts.AgentUser), result.Changed)
	if result.Kept > 0 {
		detail += fmt.Sprintf("; %d agent file(s) left at their own mode, in %d "+
			"sticky directory(ies)", result.Kept, result.Sticky)
	}
	p.step("share tree", result.Changed > 0, detail)
	return nil
}

// agentConfig writes each enrolled agent's configuration into the tree. What
// the hook costs differs by agent, Claude Code being the only one with an
// escalation to give, so the warning below names the agent it just enrolled.
func (p *project) agentConfig() error {
	if len(p.targets) == 0 {
		// The tree is shared and the instructions are written either way; what is
		// missing is the hook, and with it the redaction. A warning rather than a
		// step: a step scrolls past with the rest of a successful run, and this
		// enrolment leaves the tree shared with the client group and guarded by
		// nothing. `faramir doctor` reports the same tree for as long as it stays
		// that way.
		p.warnf("no coding agent is configured in %s, so nothing was registered and nothing this "+
			"tree runs is redacted. The tree is shared either way. `sudo faramir init-project "+
			"--agent NAME` enrols one anyway (%s)",
			p.opts.Dir, strings.Join(knownAgents(), ", "))
		p.step(labelAgentConfig, false, "no coding agent is configured in "+p.opts.Dir)
		return nil
	}
	changed := false
	var written []string
	for _, target := range p.targets {
		// Against the target's own data: the installed binary, which agent it
		// speaks to, and where it is written.
		asTarget := func(file agentFile) ([]byte, error) {
			return assetFor(target, file, p.opts.ConfigDir)
		}
		// Shared and setgid, as the walk leaves every other directory in the tree.
		// 0700 would make a directory created here the one place in an enrolled
		// tree the client group cannot enter, until a later run's walk widened it
		// and reported a change on what reads as a re-enrolment.
		made, paths, err := writeAgentFiles(p.fs, p.warnf, p.opts.Dir, p.opts.ConfigDir,
			p.uid, p.gid, 0o2770|os.ModeSetgid, true, asTarget, target.files)
		written = append(written, paths...)
		if err != nil {
			return err
		}
		changed = changed || made
		// Each warning is about this agent, so each asks whether this agent's files
		// changed rather than whether any have.
		if target.autoApprovesBash && made {
			p.warnf("Bash is now auto-approved in %s for %s: the hook rewrites every command, and a "+
				"rewritten command matches no permission rule. Its deny list is what refuses one "+
				"instead",
				p.opts.Dir, target.name)
		}
		// The account-wide half is `faramir init --agent`'s, and without it the
		// agent's file tools have no rules at all: the deny list covers the
		// operator's own ~/.ssh and ~/.config/sops, which no uid boundary reaches,
		// the agent running as the operator.
		warnMissingAccountRules(p, target)
		warnUnexpressiblePatterns(p, target)
		// Where the note stands, whether or not this run wrote anything: see
		// agentTarget.noteStands.
		if target.note != "" && (made || target.noteStands) {
			p.warnf("%s: %s", target.name, target.note)
		}
		p.warnUncommittableFiles(target)
	}
	// Named rather than counted, so an operator knows which file to merge.
	p.step(labelAgentConfig, changed, strings.Join(written, ", "))

	// What auto would have taken and this run did not, which only happens when
	// the operator named agents explicitly.
	var unenrolled []string
	for _, name := range detectedAgents(p.opts.Dir, p.agentHome) {
		enrolled := false
		for _, target := range p.targets {
			// By family: two agents sharing one tree enrolment are covered by
			// whichever of them was named, the files being the same bytes.
			if target.familyName() == agentTargets[name].familyName() {
				enrolled = true
			}
		}
		if !enrolled {
			unenrolled = append(unenrolled, name)
		}
	}
	if len(unenrolled) > 0 {
		p.warnf("this tree also has configuration for %v, which was not enrolled: "+
			"nothing those agents run here is redacted. Pass --agent to include one",
			unenrolled)
	}
	return nil
}

// warnUncommittableFiles says so when a file this enrolment wrote is one the
// agent treats as yours rather than the repository's, and git is not ignoring
// it. Claude Code adds settings.local.json to the git excludes when it writes
// the file itself; one faramir created is not covered by that.
//
// Said rather than done: what a repository ignores is the operator's to decide,
// and writing into .git or a tracked .gitignore is not this command's to do.
// Nothing in the file is secret, only specific to this machine: the binary the
// hook execs, and the directories this install occupies.
func (p *project) warnUncommittableFiles(target *agentTarget) {
	for _, file := range target.files {
		if !file.local || p.isIgnored(file.path) {
			continue
		}
		p.warnf("%s is not ignored by git, and %s reads it as yours rather than the repository's. "+
			"It names this machine's layout. Add it to .gitignore, or to .git/info/exclude to "+
			"keep that local",
			file.path, target.name)
	}
}

// isIgnored asks git, which is the only thing that can answer: the rule may be
// in a .gitignore at any level, in .git/info/exclude, or in the operator's
// global excludes.
//
// Exit 0 is ignored and exit 1 is not; anything else is git declining to answer,
// which a tree that is no repository and a host with no git both are. Those
// answer true, so the warning is withheld rather than guessed at.
func (p *project) isIgnored(rel string) bool {
	// --no-index, or a file already committed is reported as not ignored on the
	// strength of being tracked, which is not the question being put.
	cmd := exec.CommandContext(context.Background(), "git", "-C", p.opts.Dir,
		"check-ignore", "--quiet", "--no-index", "--", rel)
	err := cmd.Run()
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false
	}
	return true
}

// instructions writes the credentials section into the files this project's
// agents read as prose, between markers so a later run replaces what an earlier
// one wrote. Documentation, not enforcement: deleting the block changes
// nothing about what is reachable.
func (p *project) instructions() error {
	// One block for every agent, rendered once.
	section, err := credentialsSection(p.allowSudo)
	if err != nil {
		return err
	}
	changed, written, stale, err := p.writeSections(section)
	// Recorded before the failure, so a report says what was written as well as
	// what was not.
	p.step("instructions", changed, strings.Join(written, ", "))
	switch {
	case err != nil:
		return err
	case len(stale) > 0:
		return errors.New(strings.Join(stale, "\n"))
	}
	return nil
}

// writeSections writes the section into each file, and reports what it wrote,
// what it left as it is, and what stopped it.
func (p *project) writeSections(section string) (bool, []string, []string, error) {
	changed := false
	var written, stale []string
	for _, file := range p.instructionsFiles() {
		// Shared and setgid at every level, as the walk leaves the rest of the
		// tree: see agentConfig and ensureDirs. An agent whose rules file sits
		// under a directory none of its config files do -- antigravity's
		// .agents/rules -- has this as the only thing that creates it, and it
		// holds a file this wrote, so it is sticky like the rest of them.
		if err := p.fs.ensureDirsIn(p.opts.Dir, filepath.Dir(file.path),
			0o2770|os.ModeSetgid, 0o2770|os.ModeSetgid|os.ModeSticky,
			p.uid, p.gid); err != nil {
			return changed, written, stale, err
		}
		made, err := p.fs.sectionFile(
			file.path, section, file.head, p.uid, p.gid, p.opts.Dir)
		switch {
		case outOfDate(err):
			// Collected rather than returned: an operator fixing these wants every
			// file named, and one agent's rules file cannot cost the tree its own
			// instructions.
			stale = append(stale, sectionProblem(err, file.path, "`sudo faramir init-project`"))
			written = append(written, file.path+" (not written; see the error)")
			continue
		case err != nil:
			return changed, written, stale, err
		}
		changed = changed || made
		written = append(written, file.path)
	}
	return changed, written, stale, nil
}

// instructionsFiles are the files this enrolment writes the credentials section
// into: the tree's own, and one per agent that reads none of the names at the
// tree's root. Absolute, and in a fixed order.
func (p *project) instructionsFiles() []sectionTarget {
	out := []sectionTarget{{path: p.instructionsFile()}}
	for _, target := range p.targets {
		if rules := target.treeInstructions; rules.path != "" {
			out = append(out, sectionTarget{
				path: filepath.Join(p.opts.Dir, rules.path), head: rules.head,
			})
		}
	}
	return oneSectionPerFile(out)
}

// oneSectionPerFile drops a file an earlier one in the list already resolves
// to, so a tree whose CLAUDE.md is a link to its AGENTS.md is written once.
//
// Only these files. Every instructions file in a tree carries the same
// credentials section, so one standing in for two writes the same bytes to the
// same place and loses nothing. Two agents' settings files are each written for
// the agent that reads them, and a link between those is refused rather than
// deduplicated: see oneFileTwice.
//
// A path that cannot be resolved keeps its own name, so a dangling link stays
// in the list and is refused by refuseUnwritable, which says why.
//
// The first name wins, which puts the section in the tree's own file and leaves
// the link pointing at it.
func oneSectionPerFile(files []sectionTarget) []sectionTarget {
	out := make([]sectionTarget, 0, len(files))
	claimed := map[string]bool{}
	for _, file := range files {
		name := file.path
		if resolved, err := filepath.EvalSymlinks(name); err == nil {
			name = resolved
		}
		if claimed[name] {
			continue
		}
		claimed[name] = true
		out = append(out, file)
	}
	return out
}

// relativeInstructions is instructionsFiles as sharetree and refuseUnwritable
// take them: relative to the tree.
func (p *project) relativeInstructions() ([]string, error) {
	var out []string
	for _, file := range p.instructionsFiles() {
		rel, err := filepath.Rel(p.opts.Dir, file.path)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

// sectionTarget is one file the section goes into, with what heads it where
// this creates it. See fsys.sectionFile.
type sectionTarget struct {
	path string
	head string
}

// credentialsSection is the section `init-project` writes into a tree.
// Rendered rather than shipped as it is, for one paragraph: what an agent is
// told about waiting for an escalation only holds on a host installed with
// --allow-sudo, and on any other host it describes a refusal that never
// happens.
func credentialsSection(allowSudo bool) (string, error) {
	body, err := renderData("agent/instructions.md.snippet",
		struct{ AllowSudo bool }{AllowSudo: allowSudo})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}

func (p *project) instructionsFile() string { return treeInstructionsFile(p.opts.Dir) }

// treeInstructionsFile is the file a tree carries the credentials section in:
// the first name an agent reads that is already there, and the first name when
// none is. Answered from the tree alone, so `doctor` can ask about a tree it
// did not enrol.
func treeInstructionsFile(dir string) string {
	for _, name := range agentInstructionFiles {
		path := filepath.Join(dir, name)
		if exists(path) {
			return path
		}
	}
	return filepath.Join(dir, agentInstructionFiles[0])
}
