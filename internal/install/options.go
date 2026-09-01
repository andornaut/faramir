package install

// Everything one host provisioning run can decide, the defaults it takes when
// a flag names nothing, and the layout every step renders from.

import (
	"maps"
	"path/filepath"
	"slices"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
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

	// RepointConfig is consent to point this host's daemons at a different
	// ConfigDir. Required because the units are one set with fixed names, so a
	// second directory replaces the first rather than standing beside it: what
	// the first held stops being managed while its age key and ciphertext stay
	// on disk.
	//
	// Named for what it permits: nothing is moved, copied or removed. The old
	// directory stays exactly where it is and stops being read, which is why the
	// consent is asked for at all. Not called --force, which would collect the
	// next thing that needs overriding.
	RepointConfig bool

	// No tree is enrolled here: a tree is per project and this runs once per
	// machine. See `faramir enrol`.

	// Agents names the coding agents whose settings get the deny rules, which
	// refuse to open key material wherever the agent is working. Empty means
	// agentcfg.Auto: whichever agents the agent account's home already carries. A
	// name writes them whether or not the agent is there, and composes with auto.
	//
	// The PreToolUse hook is per project, registering it auto-approving Bash
	// there; `faramir enrol --agent` takes the same names.
	Agents []string

	// DryRun computes every answer and writes nothing. A step needing accounts
	// that do not exist yet is reported as skipped.
	DryRun bool

	// Log receives one line per step; the machine-readable answer is Report.
	Log func(string)
}

func (o *Options) applyDefaults() {
	if o.ClientGroup == "" {
		o.ClientGroup = hostlayout.DefaultClientGroup
	}
	if o.BrokerUser == "" {
		o.BrokerUser = hostlayout.DefaultBrokerUser
	}
	if o.KeeperUser == "" {
		o.KeeperUser = hostlayout.DefaultKeeperUser
	}
	// After KeeperUser, whose primary group this is: the keeper is the only
	// account that opens a managed file, so there is no membership to keep.
	if o.SecretsGroup == "" {
		o.SecretsGroup = o.KeeperUser
	}
	if o.ExecUser == "" {
		o.ExecUser = hostlayout.DefaultExecUser
	}
	if o.ConfigDir == "" {
		o.ConfigDir = hostlayout.DefaultConfigDir
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
func (o *Options) layout() (hostlayout.Layout, error) {
	layout := hostlayout.Layout{
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
		BinDir:      hostlayout.DefaultBinDir,
		LibexecDir:  hostlayout.DefaultLibexecDir,
		DocDir:      hostlayout.DefaultDocDir,
		RunDir:      hostlayout.DefaultRunDir,
		LogDir:      hostlayout.DefaultLogDir,
		SSHKey:      o.SSHKey,
		// The broker execs these as the uid holding every plaintext value, so they
		// are resolved here rather than left for a drop-in to point elsewhere.
		SshAgent: hostfs.LookPathOr("ssh-agent", "/usr/bin/ssh-agent"),
		SshAdd:   hostfs.LookPathOr("ssh-add", "/usr/bin/ssh-add"),
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
		layout.SudoRs = hostsudo.RsProbe()
	}
	layout.NotifyCommand = resolveNotifyCommand(o.NotifyCommand)
	layout.NotifyAdopted = o.notifyAdopted
	layout.Links = o.links
	layout.Blocked = o.blocked
	layout.CommandEnv = o.CommandEnv
	layout.AgentUser = o.AgentUser
	layout.CommandTimeoutSec = o.CommandTimeoutSec
	layout.CommandMaxTimeoutSec = o.CommandMaxTimeoutSec
	layout.CommandConcurrency = o.CommandConcurrency
	layout.CommandMaxMemoryPercent = o.CommandMaxMemoryPercent
	layout.BrokerMaxMemoryPercent = hostlayout.BrokerMaxMemoryPercent
	layout.CommandMaxProcessMemoryMB = o.CommandMaxProcessMemoryMB
	layout.SudoTimeoutSec = o.SudoTimeoutSec
	layout.SecretMinLength = o.SecretMinLength
	return layout, layout.Validate()
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
	out[0] = hostfs.LookPathOr(out[0], out[0])
	return out
}
