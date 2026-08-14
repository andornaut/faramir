package install

// Enrolling one project, as against provisioning the host.  `init` runs once
// per machine; this runs once per tree.  That is also what makes the working
// directory safe to default to here and unsafe there.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
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
	// Dir is the tree to enrol.  Defaults to the working directory.
	Dir string
	// Operator owns the tree and keeps owning it; this grants group access for the
	// executor's uid.
	OperatorUser string
	// ConfigDir is where the client group is learned.  A flag could disagree with
	// what the sockets admit, leaving a tree the executor cannot enter.
	ConfigDir string
	// ClientGroup overrides the group read from the config, for a tree being
	// enrolled against an install that is not on this machine: a checkout on
	// shared storage, or one prepared before its host is provisioned.  Not for
	// ordinary use.
	//
	// Not a way around a config that will not load.  This runs as root and the
	// config is 0644, so a config that is present is a config that reads; the
	// three ways the load fails are that faramir was never installed here, that
	// the config is elsewhere, and that the path given is wrong, and each of
	// those is an error naming its own fix rather than something to work around.
	ClientGroup string
	// Hook registers the PreToolUse hook in the project's agent settings, which
	// redacts the output of everything the agent runs there.  It auto-approves
	// Bash for the project: a rewritten command matches no permission rule, so the
	// hook's deny list is what refuses one.
	Hook bool
	// Agents names which coding agents to enrol.  Empty means AgentAuto:
	// whichever agents this tree already carries configuration for.  A name
	// enrols that agent whether or not it is there, and composes with auto,
	// which is how a tree is set up for one before it is installed.
	Agents []string
	DryRun bool
	Log    func(string)
}

// ProjectReport is one enrolment's outcome.
type ProjectReport struct {
	Version     string `json:"version"`
	Dir         string `json:"dir"`
	ClientGroup string `json:"group"`
	DryRun      bool   `json:"dry_run,omitempty"`
	runReport
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
	// chmod and chown and not with its walk.  See sharetree.Resolve.
	dir, err := sharetree.Resolve(named)
	if err != nil {
		return ProjectReport{}, fmt.Errorf("resolving %s: %w", named, err)
	}
	opts.Dir = dir
	if opts.ConfigDir == "" {
		opts.ConfigDir = DefaultConfigDir
	}

	// uid and gid keep rather than 0 until preflight resolves them.  Nothing
	// should write before that, and if something does, the failure is "leave
	// ownership as it is" rather than "hand the operator's file to root".
	run := &project{opts: opts, fs: fsys{dryRun: opts.DryRun}, uid: keep, gid: keep}
	run.report = ProjectReport{
		Version:   version.Version,
		Dir:       dir,
		DryRun:    opts.DryRun,
		runReport: runReport{log: opts.Log},
	}
	// The tree being changed is not the one that was named.
	if dir != named {
		run.warn("%s resolves to %s, which is the tree being enrolled", named, dir)
	}
	if err := run.preflight(); err != nil {
		return run.report, err
	}
	for _, step := range run.steps() {
		if err := step.run(); err != nil {
			// Named, for the reason `init` names its own: a run that stops partway
			// has applied everything before it and nothing after, and the first
			// step here is the one that cannot be undone.
			return run.report, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	// Recorded last: this is the one place that knows a tree was enrolled and for
	// what, and `doctor` reads it rather than guessing which agents are in use
	// from what is in a home.  Not fatal, the enrolment having already succeeded.
	if !opts.DryRun {
		names := make([]string, 0, len(run.targets))
		for _, target := range run.targets {
			names = append(names, target.name)
		}
		if err := recordEnrolment(opts.ConfigDir, EnrolledTree{
			Dir: dir, Operator: opts.OperatorUser, Agents: names,
		}); err != nil {
			run.warn("could not record this enrolment in %s, so `faramir doctor` "+
				"will not know this tree is enrolled: %v", enrolledPath(opts.ConfigDir), err)
		}
	}
	return run.report, nil
}

// steps is the order an enrolment is applied in.  The boundary is at the top
// rather than in the middle: shareTree walks the tree chowning and chmodding
// every file in it and nothing undoes that, so everything here runs after the
// irreversible part, and a refusal that can be asked at all belongs in
// preflight rather than in a step.
//
// The share goes first because what follows writes into the tree, and a file
// written before the walk is a file the walk then regroups.
func (p *project) steps() []namedStep {
	return []namedStep{
		{"share tree", p.shareTree},
		{"agent config", p.agentConfig},
		{"instructions", p.instructions},
	}
}

// preflight is every refusal this command can make, asked before the walk that
// cannot be undone.  `init` collects its own the same way and for the same
// reason: a check that fails at the step it belongs to leaves a half-enrolled
// tree to reason about.
func (p *project) preflight() error {
	if p.opts.OperatorUser == "" || p.opts.OperatorUser == "root" {
		return fmt.Errorf("name the account that works in %s: pass "+
			"--operator-user, or run through sudo so SUDO_USER carries it. The tree "+
			"belongs to somebody, and root here would chown a checkout away from "+
			"its owner", p.opts.Dir)
	}
	if os.Geteuid() != 0 && !p.opts.DryRun {
		return fmt.Errorf("faramir init-project must run as root: it " +
			"changes group ownership and modes on directories you do not own")
	}
	if err := refuseOversharing(p.opts.Dir, p.opts.OperatorUser); err != nil {
		return err
	}
	// auto looks at the tree: enrolling costs something here, so what is
	// configured is what is already set up to run in this project.  Resolved
	// before anything is written, so an unknown name stops the run before the
	// tree's ownership changes.
	targets, err := resolveAgents(p.opts.Agents, scopeTree, p.opts.Dir)
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
	p.warnMissingBinary(filepath.Join(DefaultBinDir, "faramir"))
	return p.refuseUnwritableFiles()
}

// refuseUnwritableFiles asks, before the share, the question every write into
// this tree will ask.  The share chowns and chmods every file in the tree and
// nothing undoes it, so finding out afterwards that a settings file is not the
// operator's is finding out too late.
//
// Only where the hook is being registered: --hook=false writes none of those
// files, and refusing over one it will not touch would stop an enrolment for a
// reason it does not have.  The instructions are written either way.
func (p *project) refuseUnwritableFiles() error {
	var refused []string
	instructions, err := filepath.Rel(p.opts.Dir, p.instructionsFile())
	if err != nil {
		return err
	}
	refused = append(refused, refuseUnwritable(
		p.fs, p.opts.Dir, p.uid, p.opts.Dir, []string{instructions})...)
	if p.opts.Hook {
		for _, target := range p.targets {
			refused = append(refused, refuseUnwritable(p.fs, p.opts.Dir, p.uid, p.opts.Dir,
				editedPaths(target, true, ""))...)
		}
	}
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// resolveIDs turns the operator and the client group into ids, before anything
// is written with them.
//
// A dry run is allowed to fail here and carry on: it needs no privilege, and
// the group it would share with is one `init` creates, so a tree can be asked
// about on a host that has not been provisioned yet.  The ids stay keep, and
// nothing a dry run reaches writes.
func (p *project) resolveIDs() error {
	uid, err := lookupUser(p.opts.OperatorUser)
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
// about to be pointed at is not installed.
//
// Warned rather than refused: --client-group enrols a tree for an install that
// need not be on this machine, and that tree is enrolled correctly for the host
// that will run it.  On the host that runs it, though, this is the failure
// docs/design.md predicts: the hook and the plugins fail closed, so a missing
// or too-old binary refuses every command in the project rather than running
// one unredacted.
func (p *project) warnMissingBinary(binary string) {
	if exists(binary) {
		return
	}
	p.warn("%s is not installed, and it is what every hook and plugin written "+
		"here execs. They fail closed, so on this host the agents would refuse "+
		"every command in %s rather than run one unredacted. Run `sudo faramir "+
		"init` on the host that runs this tree", binary, p.opts.Dir)
}

// refuseOversharing stops an enrolment that would share far more than a
// project.  Sharing grants the client group read and write on every file in the
// tree, and faramir-exec is in that group: for a home that carries ~/.ssh,
// ~/.config/sops/age/keys.txt, and group write on the shell configuration that
// decides what the operator's next login runs.
//
// Refused rather than warned about, the walk not being reversible.
func refuseOversharing(dir, operator string) error {
	tooBig := func(what string) error {
		return fmt.Errorf("refusing to enrol %s: it is %s. Enrolling a tree gives the "+
			"client group read and write on every file in it, and a home carries "+
			"~/.ssh and the age key under ~/.config/sops, which decrypts the same "+
			"store. Name the project directory instead", dir, what)
	}
	switch dir {
	case "/":
		return tooBig("the root of the filesystem")
	case "/home":
		return tooBig("every home on this host")
	}
	if home := homeOf(dir); home == dir {
		return tooBig("a home directory")
	}
	// The account's own home as passwd records it, which catches one outside /home
	// and /root.  Resolved, because dir is.  An unknown account fails later in
	// shareTree, with the error that names it.
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
	// the config beside the client group.  It decides one paragraph of the
	// credentials section.  False for an enrolment that named --client-group and
	// so never read a config: the section then says nothing about approvals,
	// which is the safe direction, an agent that has not been told to wait
	// re-running a command rather than working around a pause.
	allowSudo bool
	// Before any step runs, so an unknown name stops the run before the tree's
	// ownership changes.
	targets []*agentTarget
}

// step, skip and warn are the report's, forwarded so a step here spells them
// the way a step in `init` does.
func (p *project) step(name string, changed bool, detail string) {
	p.report.step(name, changed, detail)
}

func (p *project) skip(name, why string) { p.report.skip(name, why) }

func (p *project) warn(format string, args ...any) {
	p.report.warn(format, args...)
}

// resolveGroup reads the shared group out of the installed config.
// allowed_group is what the broker socket admits, so it is the only value that
// makes a shared tree usable; a flag would leave every mode right and the
// executor still unable to enter.
//
// The sudo grant is read from the same load, [sudo] exec_user being the switch
// for the whole arrangement, so an empty one is a host where no approval can be
// raised.  Which install it is read from is the question --client-group raises,
// and answered below.
func (p *project) resolveGroup() error {
	configFile := filepath.Join(p.opts.ConfigDir, "config.toml")
	cfg, err := config.Load(configFile)
	if p.opts.ClientGroup != "" {
		p.report.ClientGroup = p.opts.ClientGroup
		// The flag names an install this machine need not have, so an unreadable
		// config here is not an error: that is what the flag is for.  What it does
		// mean is that nothing else may be taken from this host's config either,
		// and the grant least of all.  Trusted only where the config loads and
		// admits the group just named, which is what says the two are one install;
		// on anything else the section says nothing about approvals, and an agent
		// that was not told to wait re-runs a refused command rather than looking
		// for a way past a pause.
		if err == nil && cfg.Server.AllowedGroup == p.opts.ClientGroup {
			p.allowSudo = cfg.Sudo.ExecUser != ""
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("cannot read the client group from %s: %w\n"+
			"Run faramir init first, pass --config-dir if the config is elsewhere, "+
			"or pass --client-group to name it directly", configFile, err)
	}
	if cfg.Server.AllowedGroup == "" {
		return fmt.Errorf("%s admits no group, so a shared tree would reach nothing. "+
			"Run `faramir init --client-group NAME`", configFile)
	}
	p.report.ClientGroup = cfg.Server.AllowedGroup
	p.allowSudo = cfg.Sudo.ExecUser != ""
	return nil
}

// warnMissingAccountRules says so when an agent's account-wide deny rules are
// not in the operator's home.  Enrolling a tree writes the per-project hook;
// the rules that hold wherever the agent works are written by `faramir init
// --agent`, and a host with one and not the other says nothing about it.
func warnMissingAccountRules(p *project, target *agentTarget) {
	if len(target.accountFiles) == 0 {
		return
	}
	home, err := operatorHomeFor(p.opts.OperatorUser)
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
	p.warn("%s's deny rules are not in the operator's home (%s), so its file "+
		"tools are refused nothing: they cover the keys under ~/.ssh and "+
		"~/.config/sops, which this enrolment does not reach. Run `sudo faramir "+
		"init --agent %s`", target.name, strings.Join(missing, ", "), target.name)
}

// operatorHomeFor is the account's home directory.
func operatorHomeFor(name string) (string, error) {
	if name == "" {
		return "", nil
	}
	entry, err := user.Lookup(name)
	if err != nil {
		return "", err
	}
	return entry.HomeDir, nil
}

// pluginData is what an agent plugin's template is rendered against: the
// binary it execs, which agent it speaks to, and the path it is written to.
// Not the install Layout, none of the last two being install-wide.
type pluginData struct {
	BinDir        string
	Agent         string
	Path          string
	DefaultExport bool
	// Dirs is this install's own directories, for a plugin that carries the
	// path rules itself rather than writing them into a config the agent reads.
	// Taken from the enrolment's --config-dir, so a store moved into a home is
	// the one refused rather than the default.
	Dirs []string
}

// assetFor is one agent file's contents, rendered whatever the asset is named,
// as an account file is.  It is how the plugins and the hook registrations get
// the installed binary's path compiled in rather than reading it from an
// environment the host controls.
func assetFor(target *agentTarget, file agentFile, configDir string) ([]byte, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	return renderData(file.asset, pluginData{
		// The compiled path, as uninstall and reload already resolve it: a
		// post-install command reads the binary where the install put it.
		BinDir:        DefaultBinDir,
		Agent:         target.name,
		Path:          file.path,
		DefaultExport: file.defaultExport,
		Dirs:          installDirs(Layout{ConfigDir: configDir}),
	})
}

// keepModes is every path this enrolment writes, relative to the tree, so
// sharing does not widen a mode this command then narrows again.
//
// Relative to the tree, which is how sharetree matches them: instructionsFile
// answers with a path under Dir.
func (p *project) keepModes() []string {
	keep := []string{}
	if rel, err := filepath.Rel(p.opts.Dir, p.instructionsFile()); err == nil {
		keep = append(keep, rel)
	}
	// p.targets, not a second resolution: auto reads the tree, and this runs
	// after files have been written into it, so resolving again here would
	// answer about the tree this command just changed.
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
		Dir: p.opts.Dir, Operator: p.opts.OperatorUser, Group: p.report.ClientGroup,
		Keep: p.keepModes(),
	})
	if err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	// The executor runs under ProtectSystem=strict with /home as its only writable
	// tree, so a tree outside it takes the group and then refuses every write with
	// EROFS.
	if homeOf(p.opts.Dir) == "" {
		p.warn("%s is outside /home, which is the only tree faramir-exec may write. "+
			"A brokered command can enter it and still gets EROFS on every write. "+
			"Add a drop-in extending ReadWritePaths= on faramir-exec.service",
			p.opts.Dir)
	}
	// What it altered, not whether it ran.  After the first run this re-applies
	// what is already there, but the first run rewrites the ownership and mode
	// of every file in the tree, and reporting that as no change tells anything
	// reading Changed that a tree it just regrouped was left alone.
	p.step("share tree", result.Changed > 0, detailWithCount(
		fmt.Sprintf("%s with group %s", p.opts.Dir, p.report.ClientGroup), result.Changed))
	return nil
}

// agentConfig writes each enrolled agent's configuration into the tree.  What
// the hook costs differs by agent (Claude Code auto-approves Bash, Gemini CLI
// has no approval to give), so the warning below reports the agent it just
// enrolled.
//
// An entry naming a path from an earlier layout is corrected rather than
// reported: a PreToolUse hook that cannot exec fails every command the agent
// runs.
func (p *project) agentConfig() error {
	if !p.opts.Hook {
		p.step("agent config", false, "--hook=false, so nothing this agent runs "+
			"here is redacted and its prompts are untouched")
		return nil
	}
	if len(p.targets) == 0 {
		// The tree is shared and the instructions are written either way; what is
		// missing is the hook, and with it the redaction.  Said rather than
		// passed over, an enrolment that configured nothing being the one case an
		// operator would read as done.
		p.step("agent config", false, fmt.Sprintf(
			"no coding agent is configured in %s, so nothing was registered and "+
				"nothing this tree runs is redacted. `sudo faramir init-project "+
				"--agent NAME` enrols one anyway (%s)",
			p.opts.Dir, strings.Join(knownAgents(), ", ")))
		return nil
	}
	changed := false
	var written []string
	for _, target := range p.targets {
		// Against the target's own data: what a tree's file interpolates is the
		// installed binary, which agent it speaks to, and where it is written.
		asTarget := func(file agentFile) ([]byte, error) {
			return assetFor(target, file, p.opts.ConfigDir)
		}
		// Shared and setgid, as the walk leaves every other directory in the
		// tree.  0700 would make a directory created here the one place in an
		// enrolled tree the client group cannot enter, so the group-readable mode
		// the files are written with would reach nothing until a later run's walk
		// widened it, and that run would then report a change on a re-enrolment
		// an operator reads as a no-op.
		made, paths, err := writeAgentFiles(p.fs, p.opts.Dir,
			p.uid, p.gid, 0o2770|os.ModeSetgid, true, asTarget, target.files)
		written = append(written, paths...)
		if err != nil {
			return err
		}
		changed = changed || made
		// Each warning is about this agent, so each asks whether this agent's
		// files changed rather than whether any have: enrolling two, where the
		// first was written and the second was already current, would otherwise
		// report the second's cost as though it had just been taken on.
		if target.autoApprovesBash && made {
			p.warn("Bash is now auto-approved in %s for %s: the hook rewrites every "+
				"command so its output can be redacted, and a rewritten command "+
				"matches no permission rule. Its deny list is what refuses one instead",
				p.opts.Dir, target.name)
		}
		// The account-wide half is `faramir init --agent`'s, and an enrolment that
		// wrote only this half leaves the agent's file tools with no rules at all:
		// the deny list covers the operator's own ~/.ssh and ~/.config/sops, which
		// no uid boundary reaches, the agent running as the operator.
		warnMissingAccountRules(p, target)
		if target.note != "" && made {
			p.warn("%s: %s", target.name, target.note)
		}
	}
	// Named rather than counted, so an operator knows which file to merge.
	p.step("agent config", changed, strings.Join(written, ", "))

	// What auto would have taken and this run did not, which only happens when
	// the operator named agents explicitly: auto enrols what it finds, so the two
	// lists differ exactly where a name narrowed it.
	var unenrolled []string
	for _, name := range detectedAgents(p.opts.Dir) {
		enrolled := false
		for _, target := range p.targets {
			if target.name == name {
				enrolled = true
			}
		}
		if !enrolled {
			unenrolled = append(unenrolled, name)
		}
	}
	if len(unenrolled) > 0 {
		p.warn("this tree also has configuration for %v, which was not enrolled: "+
			"nothing those agents run here is redacted. Pass --agent to include one",
			unenrolled)
	}
	return nil
}

// instructions writes the credentials section into the project's agent
// instructions file, between markers so a later run replaces what an earlier one
// wrote.  Documentation, not enforcement: deleting the block changes nothing
// about what is reachable.
func (p *project) instructions() error {
	path := p.instructionsFile()
	// One block for every agent, so it sits beside the other shared assets
	// rather than under the directory of the first host that wanted it.
	section, err := credentialsSection(p.allowSudo)
	if err != nil {
		return err
	}
	changed, err := p.fs.sectionFile(path, section, p.uid, p.gid, p.opts.Dir)
	switch {
	case outOfDate(err):
		p.step("instructions", false, path+" (not written; see the error)")
		return errors.New(sectionProblem(err, path, "`sudo faramir init-project`"))
	case err != nil:
		return err
	}
	p.step("instructions", changed, path)
	return nil
}

// credentialsSection is the section `init-project` writes into a tree.
//
// Rendered rather than shipped as it is, for one paragraph: what an agent is
// told about waiting for an approval only holds on a host installed with
// --allow-sudo, where a brokered command can raise one.  On any other host that
// paragraph describes a refusal that never happens, and prose an agent cannot
// act on is prose that teaches it to skim.
func credentialsSection(allowSudo bool) (string, error) {
	body, err := renderData("agent/instructions.md.snippet",
		struct{ AllowSudo bool }{AllowSudo: allowSudo})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}

func (p *project) instructionsFile() string {
	for _, name := range agentInstructionFiles {
		path := filepath.Join(p.opts.Dir, name)
		if exists(path) {
			return path
		}
	}
	return filepath.Join(p.opts.Dir, agentInstructionFiles[0])
}
