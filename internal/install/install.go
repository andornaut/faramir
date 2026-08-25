package install

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"maps"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
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
	// [sudo] section and nothing to announce. Read back off the installed config
	// when no flag names one, as the tunables below are, so a bare re-run keeps
	// the notifier instead of installing a host that announces nothing.
	NotifyCommand []string

	// The tunables, each named for what it bounds rather than for the section it
	// lands in.
	CommandEnv                map[string]string
	CommandTimeoutSec         int
	CommandMaxTimeoutSec      int
	CommandConcurrency        int
	CommandMaxMemoryPercent   int
	CommandMaxProcessMemoryMB int
	SudoTimeoutSec            int
	SecretMinLength           int

	// links is the [[secret.link]] entries, read off the installed config's base
	// file during adoption. Unexported: no flag names one, and `faramir link` is
	// what adds and removes them.
	links []config.Link
	// linksSet says the list above is deliberate, empty included, or removing the
	// last link would read as "nothing was named" and adoption would put the old
	// list back.
	linksSet bool

	// notifyAdopted says NotifyCommand above was read back off the installed
	// config rather than named on this run, so a refusal can say which of the two
	// the operator would go and change.
	notifyAdopted bool

	// blocked is the [[secret.block]] entries, adopted the same way and for the
	// same reason. `faramir block` is what changes the list.
	blocked []config.BlockedPath
	// blockedSet says the list above is deliberate, empty included.
	blockedSet bool

	// configDigest is config.toml as it was when the caller read the entries it
	// is about to write back, and configRead says the caller read at all. Both,
	// because absence is one of the answers a read gives: nil with configRead
	// set is "there was no file", which refuses a write onto one another run
	// created, and configRead unset is `init` rendering the whole file rather
	// than editing what it read.
	// Checked before the file is written: two commands each reading the config,
	// adding their own entry and writing the whole file back leave one entry, and
	// both would otherwise report the one they added as written.
	configDigest []byte
	configRead   bool

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
// The names a step reports itself under. Several flows run the same steps, and
// doctor reports on the same concerns, so each is spelled once.
const (
	labelResolveIDs    = "resolveIDs"
	labelPreconditions = "preconditions"
	labelAgentConfig   = "agent config"
	labelEnrolledTrees = "enrolled trees"
	labelConfig        = "config"
)

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
		{labelResolveIDs, r.resolveIDs},
		{labelPreconditions, r.stepPreconditions},
		{"directories", r.stepDirectories},
		{"age key", r.stepAgeKey},
		{"sops config", r.stepSopsConfig},
		{"binaries", r.stepBinaries},
		{labelConfig, r.stepConfig},
		// After the config, which is where [ssh] key is recorded, and before any
		// daemon starts: a key the broker cannot read leaves the agent holding
		// nothing.
		{"ssh key", r.stepSSHKey},
		// The other half of reaching a managed host: the key authenticates to it,
		// these say which host answering is that host.
		{"known hosts", r.stepKnownHosts},
		// After the config, which renders [sudo] from the same layout, and
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
		{labelAgentConfig, r.stepAgentConfig},
		// The same rules in every tree already enrolled, so a re-run restores what
		// a tree dropped as well as what the home did. docs/configuration.md says
		// init re-asserts every rule on each run, and until this step that was
		// true of the home alone.
		{labelEnrolledTrees, r.stepEnrolledTrees},
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
	if o.CommandMaxMemoryPercent == 0 {
		o.CommandMaxMemoryPercent = command.MaxMemoryPercent
	}
	if o.CommandMaxProcessMemoryMB == 0 {
		o.CommandMaxProcessMemoryMB = command.MaxProcessMemoryMB
	}
	if o.SudoTimeoutSec == 0 {
		o.SudoTimeoutSec = config.DefaultSudoTimeoutSec
	}
	if o.SecretMinLength == 0 {
		o.SecretMinLength = secret.MinLength
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
	// Off unless asked for, and the config template keys the whole [sudo]
	// section off it: an install that never passed --allow-sudo renders no
	// section, writes no PAM service and grants no sudoers entry.
	layout.AllowSudo = o.AllowSudo
	// Probed only where a grant is being written. On every other install it
	// decides nothing, and a version probe run to say nothing is a command in the
	// strace of every host that never asked for an escalation.
	if o.AllowSudo {
		layout.SudoRs = sudoRsProbe()
	}
	layout.NotifyCommand = resolveNotifyCommand(o.NotifyCommand)
	layout.notifyAdopted = o.notifyAdopted
	layout.Links = o.links
	layout.Blocked = o.blocked
	layout.CommandEnv = o.CommandEnv
	layout.AgentUser = o.AgentUser
	layout.CommandTimeoutSec = o.CommandTimeoutSec
	layout.CommandMaxTimeoutSec = o.CommandMaxTimeoutSec
	layout.CommandConcurrency = o.CommandConcurrency
	layout.CommandMaxMemoryPercent = o.CommandMaxMemoryPercent
	layout.BrokerMaxMemoryPercent = BrokerMaxMemoryPercent
	layout.CommandMaxProcessMemoryMB = o.CommandMaxProcessMemoryMB
	layout.SudoTimeoutSec = o.SudoTimeoutSec
	layout.SecretMinLength = o.SecretMinLength
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
		// Reached by `block` and `link` as well, which have no flag of their own:
		// they read what the config records, and `init` is what records it.
		return errors.New("name the account the coding agent runs as: run through " +
			"sudo so SUDO_USER carries it, or record it with " +
			"`faramir init --agent-user`. It must not be root")
	}
	if !userExists(r.opts.AgentUser) {
		return fmt.Errorf("no such user: %s", r.opts.AgentUser)
	}
	// Held to what the executor will fork, and here rather than at the loader
	// alone: a value above it renders a config.toml the daemons then refuse,
	// which is a host with no broker where the answer is one number.
	if r.opts.CommandConcurrency > config.MaxConcurrentRuns {
		return fmt.Errorf("--command-concurrency %d is above the %d the executor forks at once, so the "+
			"surplus is refused by the executor after the run is recorded as started. Name %d "+
			"or fewer",
			r.opts.CommandConcurrency, config.MaxConcurrentRuns, config.MaxConcurrentRuns)
	}
	// The same bound from the other side, and negative rather than below 1:
	// zero is the unset signal every tunable shares, so applyDefaults turns it
	// into the default and a caller that builds Options directly leaves it there.
	// Refusing zero here would refuse every such caller for a value nobody typed.
	//
	// A negative one panics the broker as it sizes its slot channel, so the
	// loader refuses it and the config is never written. That arrives as a parse
	// error about a file the operator did not type, after preflight has already
	// passed; named here it is the flag that is wrong.
	if r.opts.CommandConcurrency < 0 {
		return fmt.Errorf("--command-concurrency %d is negative, and a broker cannot "+
			"size itself to run fewer than no commands at all. Name 1 or more",
			r.opts.CommandConcurrency)
	}
	r.warnLongSudoTimeout()
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
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is inside it: installing now "+
			"writes plaintext to the backing directory. Log in as its owner first",
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
	installed := unitConfigDir(brokerUnit)
	if installed == "" || installed == r.layout.ConfigDir {
		return nil
	}
	if !r.opts.MoveConfig {
		// A dry run reports and writes nothing, so the move is what it has to
		// report: refusing here would mean consenting to a move to preview it.
		if r.opts.DryRun {
			r.warnf("this host's daemons load %s, and this run names %s. A real run would be refused: "+
				"pass --move-config to move them, or leave --config-dir out",
				installed, r.layout.ConfigDir)
			return nil
		}
		return fmt.Errorf("this host's daemons load %s, and this run names %s.\nThere is one set of units, "+
			"so the daemons would move and %s would be left holding its age key and its "+
			"ciphertext, no longer redacted.\nPass --move-config to move them, then retire %s "+
			"yourself. To provision the install this host has, leave --config-dir out",
			installed, r.layout.ConfigDir, installed, installed)
	}
	// Consented to, and still worth naming: what is left behind is key material
	// and every value it opens. Said once, here, and by nothing afterwards: the
	// old directory is not part of the install any more, so no later command
	// looks at it. That is the reason to name the files and the commands rather
	// than the directory, since this is the only reading the operator gets.
	managed, _ := filepath.Glob(filepath.Join(installed, "secrets", "*.sops.yml"))
	key := filepath.Join(installed, "age.key")
	store := filepath.Join(installed, "secrets")
	width := max(len(key), len(store))
	r.warnf("the daemons now load %s, and %s is no longer part of this install: "+
		"nothing there is managed, nothing in it is redacted, and no later "+
		"`faramir doctor` will mention it again.\n"+
		"  %-*s  the key that opens what is beside it\n"+
		"  %-*s  %d managed file(s), every value in them covered by nothing now\n"+
		"Re-encrypt what you still need where the daemons now look, check it is "+
		"served with `faramir refs`, and then remove the old directory:\n"+
		"  sudo rm -rf %s",
		r.layout.ConfigDir, installed,
		width, key, width, store, len(managed), installed)
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
	paths := homeEditedPaths(targets)
	refused := refuseUnwritable(r.fs, r.operatorHome, r.operatorUID, "", paths)
	// And the directories those files sit in, which stepAgentConfig creates when
	// they are missing. The home's own question, not the tree's: a symlinked
	// component there is the operator's dotfiles, and writeAgentFiles reads
	// through it on purpose. 0700 is the mode it makes them with.
	refused = append(refused, refuseUncreatableDirs(
		r.operatorHome, 0o700, r.operatorUID, r.operatorGID, paths)...)
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
			"nothing was written: %w: %s%s", checkErr, strings.TrimSpace(string(out)),
			sudoRsNote(visudo))
	}
	return nil
}

// sudoRsNote names the version floor the grant sits on, or "".
//
// The grant is rendered for whichever sudo this host has, so a rejection is no
// longer a question of which implementation is installed but of how old it is.
// Both grew `noninteractive_auth` after their first releases, and it is the one
// setting here that a sudo old enough will not know: `unknown setting` from
// visudo reads as a typo in a directive faramir wrote deliberately, and every
// other line of the grant is reported as invalid with it.
//
// Read only once the check has failed. A version probe on every install would be
// a command run to say nothing on every host that works.
func sudoRsNote(visudo string) string {
	out, err := exec.CommandContext(context.Background(), visudo, "-V").CombinedOutput()
	if err != nil {
		return ""
	}
	banner := strings.TrimSpace(firstLine(string(out)))
	floor, older := "sudo 1.9.11", olderThanFloor(banner)
	// bannerIsSudoRs, not a substring: sudo-rs 0.2.2 answers visudo -V with
	// "visudo version 0.2.2" and names no implementation, and that is exactly the
	// release this note is most likely to be printed for.
	if bannerIsSudoRs(banner) {
		floor = "sudo-rs 0.2.9"
	}
	// Only where the version is a cause this rejection could have. Every other
	// rejection is about the file, which visudo has already said its piece about,
	// and a note on all of them sends operators after a sudo upgrade they do not
	// need. Silent where the version could not be read: a guess is worse than
	// nothing.
	if !older {
		return ""
	}
	return "\nThis host reports " + banner + ". The grant needs " + floor +
		"or newer, that being where noninteractive_auth arrived: without it `sudo -n` fails " +
		"before the PAM stack runs, so no question is put. Upgrade sudo, or install without " +
		"--allow-sudo"
}

// olderThanFloor reports whether a version banner names a release without
// noninteractive_auth: sudo before 1.9.11, sudo-rs before 0.2.9. A banner it
// cannot parse answers false, so an unrecognised sudo draws no note.
func olderThanFloor(banner string) bool {
	digits := func(s string) []int {
		var out []int
		for _, part := range strings.FieldsFunc(s, func(r rune) bool {
			return r < '0' || r > '9'
		}) {
			n, err := strconv.Atoi(part)
			if err != nil {
				return nil
			}
			out = append(out, n)
		}
		return out
	}
	fields := strings.Fields(banner)
	version := ""
	for _, field := range fields {
		if strings.ContainsAny(field, "0123456789") && strings.Contains(field, ".") {
			version = field
			break
		}
	}
	parts := digits(version)
	if len(parts) < 3 {
		return false
	}
	floor := []int{1, 9, 11}
	if bannerIsSudoRs(banner) {
		floor = []int{0, 2, 9}
	}
	for i := range floor {
		if parts[i] != floor[i] {
			return parts[i] < floor[i]
		}
	}
	return false
}

// firstLine is what a version banner's first line says, both implementations
// printing more than one.
func firstLine(text string) string {
	head, _, _ := strings.Cut(text, "\n")
	return head
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
		return fmt.Errorf("%s is a symlink to %s, and faramir asserts the mode and owner of that path, which "+
			"through a link would land on the target: nothing has been installed. Replace it "+
			"with a real file or directory, or move the install with --config-dir",
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
	r.warnf("--sudo-timeout-sec %d is longer than the %ds a brokered command may run, "+
		"and the command waits inside sudo for the whole question, so a question is "+
		"held to %ds. Raise --command-max-timeout-sec to give an answer longer to arrive",
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
