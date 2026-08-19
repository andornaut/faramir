package install

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/version"
)

// Options is one `faramir init` invocation: everything an operator can decide.
// The paths that follow are in Layout.
type Options struct {
	// AgentUser is the account the coding agent runs as. It has no account of
	// its own: the work it does is the operator's, and a separate uid could reach
	// none of it.
	AgentUser string

	ClientGroup  string
	SecretsGroup string
	BrokerUser   string
	KeeperUser   string
	ExecUser     string

	// ConfigDir holds config.toml, the age key and the secrets directory. One
	// path, so secrets in an encrypted home have the key that opens them there
	// too.
	ConfigDir string

	// SSHKey relocates the identity the broker lends through an agent it owns, so
	// the executor can authenticate with it without reading it. Empty takes the
	// default beside the age key; see Layout.SSHKey. It names a keypair, and the
	// broker holds both halves.
	SSHKey string

	// KnownHosts is a known_hosts file to pin for the executor, copied to
	// Layout.ExecKnownHosts. Empty pins nothing, which is the host where
	// /etc/ssh/ssh_known_hosts already covers every account. A copy rather than
	// a reference, the executor not being able to read the operator's 0700
	// ~/.ssh; only public host keys travel.
	KnownHosts string

	// AllowSudo lets a brokered command ask to become root on this host, so one
	// run can configure the fleet and the controller together. Off by default,
	// being the one place the executor's reach grows; see docs/escalation.md.
	// Re-running without it removes the grant.
	AllowSudo bool

	// NotifyCommand announces a pending escalation, "{prompt}" being the line the
	// broker builds and "{id}" the question to answer. Empty leaves `faramir
	// escalations --watch` as the only place a question shows up.
	//
	// A flag rather than a drop-in because the broker execs it as the uid holding
	// every decrypted value. Requires AllowSudo: without the grant there is no
	// [escalation] section and nothing to announce.
	NotifyCommand []string

	// The tunables, each named for what it bounds rather than for the section it
	// lands in.
	CommandEnv           map[string]string
	CommandTimeoutSec    int
	CommandMaxTimeoutSec int
	CommandConcurrency   int
	EscalationTimeoutSec int
	SecretMinLength      int
	SecretMinRefreshSec  int

	// links is the [[secret.link]] entries, read off the installed config's base
	// file during adoption. Unexported: no flag names one, and `faramir link` is
	// what adds and removes them.
	links []config.Link
	// linksSet says the list above is deliberate, empty included, or removing the
	// last link would read as "nothing was named" and adoption would put the old
	// list back.
	linksSet bool

	// MoveConfig is consent to point this host's daemons at a different ConfigDir.
	// Required because the units are one set with fixed names, so a second
	// directory replaces the first rather than standing beside it: what the first
	// held stops being managed while its age key and ciphertext stay on disk.
	//
	// Named for the one thing it permits rather than called --force, which would
	// collect the next thing that needs overriding.
	MoveConfig bool

	// No tree is enrolled here: a tree is per project and this runs once per
	// machine. See `faramir init-project`.

	// Agents names the coding agents whose settings get the deny rules, which
	// refuse to open key material wherever the agent is working. Empty means
	// AgentAuto: whichever agents the agent account's home already carries. A
	// name writes them whether or not the agent is there, and composes with auto.
	//
	// The PreToolUse hook is per project, registering it auto-approving Bash
	// there; `faramir init-project --agent` takes the same names.
	Agents []string

	// DryRun computes every answer and writes nothing. A step needing accounts
	// that do not exist yet is reported as skipped.
	DryRun bool

	// Log receives one line per step; the machine-readable answer is Report.
	Log func(string)
}

// Step is one unit of work and whether it changed anything, so a configuration
// manager reads Changed rather than stat-ing the host.
type Step struct {
	Name    string `json:"step"`
	Changed bool   `json:"changed"`
	Skipped bool   `json:"skipped,omitempty"`
	Detail  string `json:"detail,omitempty"`
}

// runReport is what every command's report carries, embedded by Report and
// ProjectReport so the recording is written once.
type runReport struct {
	Changed bool   `json:"changed"`
	Steps   []Step `json:"steps"`
	// Warnings are the things that install cleanly and then do not work. Not
	// failures, each having a legitimate shape.
	Warnings []string `json:"warnings,omitempty"`
	// log receives one line per step. Unexported, so it is no part of the
	// document either report serialises to.
	log func(string)
}

// step records one unit of work and its outcome.
func (r *runReport) step(name string, changed bool, detail string) {
	r.Steps = append(r.Steps, Step{Name: name, Changed: changed, Detail: detail})
	if changed {
		r.Changed = true
	}
	if r.log == nil {
		return
	}
	mark := "ok"
	if changed {
		mark = "changed"
	}
	line := fmt.Sprintf("%-9s %s", mark, name)
	if detail != "" {
		line += ": " + detail
	}
	r.log(line)
}

// skip records a step that could not be evaluated. Only under DryRun.
func (r *runReport) skip(name, why string) {
	r.Steps = append(r.Steps, Step{Name: name, Skipped: true, Detail: why})
	if r.log != nil {
		r.log(fmt.Sprintf("%-9s %s: %s", "skipped", name, why))
	}
}

func (r *runReport) warnf(format string, args ...any) {
	r.Warnings = append(r.Warnings, fmt.Sprintf(format, args...))
}

// Report is the whole run.
type Report struct {
	runReport

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

type runner struct {
	opts   Options
	layout Layout
	fs     fsys
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
	agentTargets []*agentTarget

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
		opts:   opts,
		layout: layout,
		fs:     fsys{dryRun: opts.DryRun},
		report: Report{
			Version:   version.Version,
			DryRun:    opts.DryRun,
			runReport: runReport{log: opts.Log},
		},
		adopted: adopted,
	}
	if self, err := os.Executable(); err == nil {
		run.binaries = filepath.Dir(self)
	}
	if err := run.preflight(); err != nil {
		return nil, err
	}
	return run, nil
}

// apply runs the steps given, in order.
func (r *runner) apply(steps []namedStep) (Report, error) {
	for _, step := range steps {
		if err := step.run(); err != nil {
			// Named, because a run that stops partway has applied everything before
			// it and nothing after. The steps that hand a file to an account are all
			// after stepPreconditions, so a refusal there has changed no ownership.
			return r.report, fmt.Errorf("%s: %w", step.name, err)
		}
	}
	return r.report, nil
}

// namedStep is one step and what to call it when a run stops there.
type namedStep struct {
	name string
	run  func() error
}

// steps is the order the install is applied in, which is itself a boundary:
// everything before stepPreconditions adds accounts and groups and can be
// repeated, everything after hands existing files to them and cannot be undone
// by running init again. A refusal that a later step could raise and
// stepPreconditions can ask belongs in stepPreconditions.
func (r *runner) steps() []namedStep {
	return []namedStep{
		{"adopted", r.stepAdopted},
		{"accounts", r.stepAccounts},
		{"resolveIDs", r.resolveIDs},
		{"preconditions", r.stepPreconditions},
		{"directories", r.stepDirectories},
		{"age key", r.stepAgeKey},
		{"sops config", r.stepSopsConfig},
		{"binaries", r.stepBinaries},
		{"config", r.stepConfig},
		// After the config, which is where [ssh] key is recorded, and before any
		// daemon starts: a key the broker cannot read leaves the agent holding
		// nothing.
		{"ssh key", r.stepSSHKey},
		// The other half of reaching a managed host: the key authenticates to it,
		// these say which host answering is that host.
		{"known hosts", r.stepKnownHosts},
		// After the config, which renders [escalation] from the same layout, and
		// before anything restarts a daemon: a broker that came up without the PAM
		// service and the sudoers entry in place would refuse every escalation
		// until the next activation.
		{"sudo grant", r.stepSudoGrant},
		// Before the units are written: it grants the traversal that lets a service
		// uid reach a config under the agent account's home.
		{"reachable", r.stepReachable},
		// After the step above, this granting traversal down to a file in the same
		// home: the two must not race to regroup the directories they share.
		{"linked files", r.stepLinkAccess},
		{"units", r.stepUnits},
		{"systemd", r.stepSystemd},
		{"agent config", r.stepAgentConfig},
		{"validate", r.stepValidate},
	}
}

func (o *Options) applyDefaults() {
	if o.ClientGroup == "" {
		o.ClientGroup = DefaultClientGroup
	}
	if o.BrokerUser == "" {
		o.BrokerUser = DefaultBrokerUser
	}
	if o.KeeperUser == "" {
		o.KeeperUser = DefaultKeeperUser
	}
	// After KeeperUser, whose primary group this is: the keeper is the only
	// account that opens a managed file, so there is no membership to keep.
	if o.SecretsGroup == "" {
		o.SecretsGroup = o.KeeperUser
	}
	if o.ExecUser == "" {
		o.ExecUser = DefaultExecUser
	}
	if o.ConfigDir == "" {
		o.ConfigDir = DefaultConfigDir
	}
	// From the loader, so the file this writes and the file it would read agree
	// on what a default is.
	command, secret := config.DefaultCommand(), config.DefaultSecret()
	if o.CommandTimeoutSec == 0 {
		o.CommandTimeoutSec = command.TimeoutSec
	}
	if o.CommandMaxTimeoutSec == 0 {
		o.CommandMaxTimeoutSec = command.MaxTimeoutSec
	}
	if o.CommandConcurrency == 0 {
		o.CommandConcurrency = command.Concurrency
	}
	if o.EscalationTimeoutSec == 0 {
		o.EscalationTimeoutSec = config.DefaultEscalationTimeoutSec
	}
	if o.SecretMinLength == 0 {
		o.SecretMinLength = secret.MinLength
	}
	if o.SecretMinRefreshSec == 0 {
		o.SecretMinRefreshSec = secret.MinRefreshSec
	}
	// Merged, never replaced: a flag naming one variable keeps the rest.
	env := command.Env
	maps.Copy(env, o.CommandEnv)
	o.CommandEnv = env
}

// layout derives the paths from the options and checks them.
func (o *Options) layout() (Layout, error) {
	layout := Layout{
		ClientGroup:  o.ClientGroup,
		SecretsGroup: o.SecretsGroup,
		BrokerUser:   o.BrokerUser,
		KeeperUser:   o.KeeperUser,
		ExecUser:     o.ExecUser,
		// Replaced by resolveIDs once the accounts exist; a dry run keeps them.
		ExecGroup:   o.ExecUser,
		BrokerGroup: o.BrokerUser,
		KeeperGroup: o.KeeperUser,
		ConfigDir:   filepath.Clean(o.ConfigDir),
		BinDir:      DefaultBinDir,
		LibexecDir:  DefaultLibexecDir,
		DocDir:      DefaultDocDir,
		RunDir:      DefaultRunDir,
		LogDir:      DefaultLogDir,
		SSHKey:      o.SSHKey,
		// The broker execs these as the uid holding every plaintext value, so they
		// are resolved here rather than left for a drop-in to point elsewhere.
		SshAgent: lookPathOr("ssh-agent", "/usr/bin/ssh-agent"),
		SshAdd:   lookPathOr("ssh-add", "/usr/bin/ssh-add"),
	}
	layout.ConfigFile = filepath.Join(layout.ConfigDir, "config.toml")
	// Beside the config, even inside the agent account's home: what keeps the
	// operator out is the key's 0400 keeper ownership, owning the directory being
	// permission to unlink the file rather than to read it. Following the config
	// puts the key inside an encrypted home when the secrets directory is already
	// there.
	layout.AgeKeyPath = filepath.Join(layout.ConfigDir, "age.key")
	if layout.SSHKey == "" {
		layout.SSHKey = filepath.Join(layout.ConfigDir, "id_ed25519")
	}
	// Off unless asked for, and the config template keys the whole [escalation]
	// section off it: an install that never passed --allow-sudo renders no
	// section, writes no PAM service and grants no sudoers entry.
	layout.AllowSudo = o.AllowSudo
	layout.NotifyCommand = resolveNotifyCommand(o.NotifyCommand)
	layout.Links = o.links
	layout.CommandEnv = o.CommandEnv
	layout.CommandTimeoutSec = o.CommandTimeoutSec
	layout.CommandMaxTimeoutSec = o.CommandMaxTimeoutSec
	layout.CommandConcurrency = o.CommandConcurrency
	layout.EscalationTimeoutSec = o.EscalationTimeoutSec
	layout.SecretMinLength = o.SecretMinLength
	layout.SecretMinRefreshSec = o.SecretMinRefreshSec
	return layout, layout.validate()
}

// resolveNotifyCommand pins argv[0] to the file it names now, leaving the
// arguments alone, as ssh_agent and ssh_add are: the broker execs this as the
// uid holding every decrypted value, so the install decides which file a bare
// name lands on rather than the broker's PATH at the moment a question is
// raised. A name that resolves to nothing is left as it was, for
// validateNotifyCommand to refuse.
func resolveNotifyCommand(argv []string) []string {
	if len(argv) == 0 {
		return nil
	}
	out := slices.Clone(argv)
	out[0] = lookPathOr(out[0], out[0])
	return out
}

// preflight refuses the run before anything is written, each of these otherwise
// surfacing with the install half applied.
func (r *runner) preflight() error {
	if os.Geteuid() != 0 && !r.opts.DryRun {
		return errors.New("faramir init must run as root: it creates accounts, " +
			"writes under /etc and installs systemd units")
	}
	if r.opts.AgentUser == "" || r.opts.AgentUser == "root" {
		return errors.New("name the account the coding agent runs as: pass --agent-user, " +
			"or run through sudo so SUDO_USER carries it. It must not be root: " +
			"the operator owns the checkouts a brokered command runs in")
	}
	if !userExists(r.opts.AgentUser) {
		return fmt.Errorf("no such user: %s", r.opts.AgentUser)
	}
	// Read before an account or a key exists: reporting a typo at the step would
	// leave a half-finished install to re-run.
	if r.opts.KnownHosts != "" {
		if _, _, err := readKnownHosts(r.opts.KnownHosts); err != nil {
			return fmt.Errorf("--known-hosts: %w", err)
		}
	}
	// An encrypted home is a different directory before its owner logs in, so a
	// write lands in the backing directory and is shadowed the moment it mounts.
	// The config directory answers for the secrets directory and the key too.
	if home := homeOf(r.layout.ConfigDir); home != "" && looksEncrypted(home) && !homeIsMounted(home) {
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is "+
			"inside it. Installing now would write plaintext to the backing directory, "+
			"where it is hidden once the home mounts. Log in as its owner first",
			home, r.layout.ConfigDir)
	}
	// The config directory is the one faramir creates whose parent can belong to
	// the operator, and ensureDir chowns every ancestor it creates: a ~/.config
	// made that way is root-owned and breaks every other tool that keeps state
	// there.
	if parent := filepath.Dir(r.layout.ConfigDir); !exists(parent) {
		return fmt.Errorf("%s does not exist, and %s is inside it. Create it with "+
			"the ownership you want first: creating it here would hand it to root",
			parent, r.layout.ConfigDir)
	}
	if err := r.refuseConfigMove(); err != nil {
		return err
	}
	if err := r.refuseSymlinks(); err != nil {
		return err
	}
	// The binaries are built ahead of time. Checked here rather than at the
	// install step, which is after the accounts and the age key exist.
	if r.binaries == "" {
		return errors.New("cannot find the directory this faramir was run from")
	}
	var missing []string
	for _, name := range installedBinaries {
		if !exists(filepath.Join(r.binaries, name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not built in %s: %s. Run 'make build', then run the "+
			"faramir it built", r.binaries, strings.Join(missing, ", "))
	}
	return nil
}

// refuseConfigMove stops a run that would point this host's daemons at a
// different config directory, unless it was asked to.
//
// There is one set of units, with fixed names, so naming a second directory
// repoints the daemons and leaves the first directory where it stands: the refs
// it held leave the value set, so a brokered command that prints one of those
// values prints it, while its age key and ciphertext stay on disk. doctor
// examines only the install the units name.
//
// A flag-less re-run never reaches this: init resolves the config directory
// from the running broker and then from the unit.
func (r *runner) refuseConfigMove() error {
	installed := unitConfigDir("faramir-broker.service")
	if installed == "" || installed == r.layout.ConfigDir {
		return nil
	}
	if !r.opts.MoveConfig {
		// A dry run reports and writes nothing, so the move is what it has to
		// report: refusing here would mean consenting to a move to preview it.
		if r.opts.DryRun {
			r.warnf("this host's daemons load %s, and this run names %s. A run that "+
				"was not a dry run would be refused: pass --move-config to move them, "+
				"or leave --config-dir out to provision the install this host has",
				installed, r.layout.ConfigDir)
			return nil
		}
		return fmt.Errorf("this host's daemons load %s, and this run names %s.\n"+
			"There is one set of units, so the second does not stand beside the "+
			"first: the daemons would move and %s would be left holding its age key "+
			"and its ciphertext, with the refs it serves no longer in the value set "+
			"and no longer redacted.\n"+
			"Pass --move-config to move them, then retire %s yourself. To provision "+
			"the install this host already has, leave --config-dir out",
			installed, r.layout.ConfigDir, installed, installed)
	}
	// Consented to, and still worth naming: what is left behind is key
	// material.
	r.warnf("the daemons now load %s. %s is left as it stands, including %s and "+
		"the secrets directory: nothing there is managed or redacted from now on. "+
		"Retire it when its values are re-encrypted where the daemons look",
		r.layout.ConfigDir, installed, filepath.Join(installed, "age.key"))
	return nil
}

// stepPreconditions raises, before anything is handed over, every refusal a
// later step would raise once it was too late to re-run cleanly. It reports
// nothing when it passes, these being preconditions rather than work.
func (r *runner) stepPreconditions() error {
	// Asked whether or not this is a dry run: a dry run must not answer "this
	// would work" about a home where it would not. editedFile reports nothing it
	// cannot read unprivileged, so what a dry run cannot see it does not claim.
	if err := r.refuseUnwritableAgentFiles(); err != nil {
		return err
	}
	if r.opts.DryRun {
		return nil
	}
	if err := r.refuseUnadoptableSSHKey(); err != nil {
		return err
	}
	return r.refuseInvalidSudoers()
}

// refuseUnwritableAgentFiles asks the question stepAgentConfig asks of every
// file it edits, before anything has been handed to an account: failing there
// leaves a host whose units are installed and whose daemons have been reloaded.
// The targets are resolved here and kept, so the question and the writing agree
// on which agents this run is about.
func (r *runner) refuseUnwritableAgentFiles() error {
	targets, err := resolveAgents(r.opts.Agents, scopeHome, r.operatorHome)
	if err != nil {
		return err
	}
	r.agentTargets = targets
	refused := refuseUnwritable(r.fs, r.operatorHome, r.operatorUID, "",
		homeEditedPaths(targets))
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// refuseUnadoptableSSHKey asks the question stepSSHKey asks, at a point where
// the answer costs nothing. Only for a key already on disk: one this run mints
// is adopted by whoever it is minted for.
func (r *runner) refuseUnadoptableSSHKey() error {
	if !exists(r.layout.SSHKey) {
		return nil
	}
	return r.checkSSHKey(r.layout.SSHKey, r.brokerUID, r.brokerGID)
}

// refuseInvalidSudoers has visudo judge the grant before the run reaches the
// step that installs it. Rendered to a file of its own rather than into
// sudoers.d, which sudo reads. Nothing here is the operator's text, so what
// this catches is a sudo too old for a directive.
func (r *runner) refuseInvalidSudoers() error {
	// The same two directories stepSudoGrant needs: gating on sudoers.d alone
	// would fail the install over a grant that step skips with a warning.
	if !r.layout.AllowSudo || !exists(sudoersDir) || !exists(pamDir) {
		return nil
	}
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		return nil
	}
	body, err := render("etc/sudoers.tmpl", r.layout)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "faramir-sudoers")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	candidate := filepath.Join(dir, "faramir")
	// 0600, not the 0440 the installed file gets: nothing reads this but the
	// visudo below, which parses a file at any mode. The mode sudo requires is
	// asserted where the real file is written.
	if err := os.WriteFile(candidate, body, 0o600); err != nil {
		return err
	}
	if out, checkErr := exec.CommandContext(context.Background(), visudo, "-cf", candidate).
		CombinedOutput(); checkErr != nil {
		return fmt.Errorf("visudo rejects the grant --allow-sudo would install, so "+
			"nothing was written: %w: %s", checkErr, strings.TrimSpace(string(out)))
	}
	return nil
}

// refuseSymlinks fails the run when any path this install asserts a mode or an
// owner on is a symlink. Those assertions are what keep the file out of the
// agent's reach, and applying one through a link applies it to the target
// instead.
//
// A precondition rather than a refusal at each step, so the answer is one
// message with the host untouched. It does not replace the O_NOFOLLOW repair
// in ensureOwnership: nothing stops the path being re-pointed after this runs,
// so what it provides is the diagnosis rather than the enforcement.
func (r *runner) refuseSymlinks() error {
	secretsDir := r.layout.SecretsDir()
	// The directories before what is in them, so a linked directory is named as
	// itself rather than through the entries it lists.
	paths := []string{
		r.layout.ConfigDir,
		secretsDir,
		r.layout.SopsConfigPath(),
		r.layout.AgeKeyPath,
		r.layout.LogDir,
		r.layout.AuditLogPath(),
	}
	for _, dir := range []string{secretsDir} {
		// Absent, or a dry run that cannot look inside; either way there is nothing
		// here to answer for.
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, _ := os.Readlink(path)
		return fmt.Errorf("%s is a symlink to %s. faramir asserts the mode and owner "+
			"of that path, and through a link they would land on the target instead, "+
			"so nothing has been installed. Replace it with a regular file or "+
			"directory. To keep the data elsewhere, move the install itself with "+
			"--config-dir, or mount the directory rather than linking it",
			path, target)
	}
	return nil
}

// step, skip and warnf are the report's, forwarded so every caller in this
// package spells them the same way.
func (r *runner) step(name string, changed bool, detail string) {
	r.report.step(name, changed, detail)
}

func (r *runner) skip(name, why string) { r.report.skip(name, why) }

// reportPresence is the dry-run answer for a step that only asks whether a file
// is there. Nothing is opened: several are key material.
func (r *runner) reportPresence(name, path, wouldCreate string) {
	present, known := probe(path)
	switch {
	case !known:
		r.skip(name, "cannot tell whether "+path+" is there without root")
	case present:
		r.step(name, false, "keeping "+path)
	default:
		r.step(name, true, wouldCreate+" "+path)
	}
}

// restartFor records that a running daemon is now behind what is installed.
func (r *runner) restartFor(what string) {
	r.needsRestart = true
	if !slices.Contains(r.restartReasons, what) {
		r.restartReasons = append(r.restartReasons, what)
	}
}

func (r *runner) warnf(format string, args ...any) {
	r.report.warnf(format, args...)
}

// command runs a program and returns its standard output. stdout alone: the
// broker prints its --check report there and logs on stderr, so a combined
// capture would make every report unparseable. stderr is carried in the
// error.
func (r *runner) command(name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// commandCombined is command for the programs whose answer is on stderr.
// systemd-analyze verify reports there and exits 0 either way.
func (r *runner) commandCombined(name string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
