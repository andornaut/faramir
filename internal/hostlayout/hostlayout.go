// Package hostlayout is what an install is, as values: the accounts, the shared
// group, the directories, the tunables, and every path derived from them.
//
// One Layout, because the same values have to reach several files that must
// agree. The systemd units, config.toml, the sudoers grant, the PAM service and
// every agent's deny rules all render from it, so a service uid or a directory
// is decided once and read everywhere rather than spelled per template.
//
// It writes nothing and asks the host nothing. What provisions a host is
// internal/install; what reads one back is internal/install's doctor. Both
// build a Layout first, and a check that compares them is comparing values from
// one source rather than two readings.
package hostlayout

import (
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
)

// Default paths. Only ConfigDir is meant to be moved; the rest are here so the
// templates have one source for them.
const (
	DefaultConfigDir  = "/etc/faramir"
	DefaultBinDir     = "/usr/local/bin"
	DefaultLibexecDir = "/usr/local/libexec/faramir"
	DefaultDocDir     = "/usr/local/share/doc/faramir"
	DefaultRunDir     = "/run/faramir"
	DefaultLogDir     = "/var/log/faramir"

	// PamServiceName is not derived from a layout field: the path is the
	// distribution's.
	PamServiceName = "faramir-sudo"
	// DefaultClientGroup is named for what membership grants rather than for who
	// tends to hold it. A member may ask the broker for any managed value, and
	// once a tree is enrolled the group is on every directory from the
	// operator's home down, so a name like "dev" invites adding a colleague for
	// an unrelated reason and handing them the value set. It is also a name a
	// host is likely to have already, and an install adopts a group that exists
	// rather than refusing, so a collision grants every current member at
	// install time.
	DefaultClientGroup = "faramir-client"
	DefaultBrokerUser  = "faramir-broker"
	DefaultKeeperUser  = "faramir-keeper"
	DefaultExecUser    = "faramir-exec"
)

// The flags that move a daemon to another account, beside the defaults they
// replace. Named once because three files spell each of them: what adopts an
// existing install, what diagnoses one, and what refuses an operator that is one
// of these accounts.
const (
	BrokerUserFlag = "--broker-user"
	KeeperUserFlag = "--keeper-user"
	ExecUserFlag   = "--exec-user"
)

// Where the distribution keeps the two files a sudo grant needs, the audit
// log's rotation rule, and logrotate's own record of what it has rotated.
// Variables rather than constants so a test can point at files it wrote: a host
// with one and not the other is a state no test can create at the real paths.
var (
	SudoersDir = "/etc/sudoers.d"
	// PamDir is internal/escalation's, not a second copy: the broker reads the
	// same directory when it answers whether this host can escalate at all, and a
	// test that moved one of two would exercise code still looking at /etc.
	PamDir          = escalation.PamDir
	SudoersFile     = SudoersDir + "/faramir"
	PamServiceFile  = PamDir + "/" + PamServiceName
	LogrotateConfig = "/etc/logrotate.d/faramir"

	// LogrotateStatePaths is where logrotate keeps its record of what it has
	// rotated. The path is compiled into logrotate rather than configured, and
	// distributions do not agree on it, so the first that exists answers.
	LogrotateStatePaths = []string{
		"/var/lib/logrotate/status",           // Debian, Ubuntu
		"/var/lib/logrotate.status",           // older Debian
		"/var/lib/logrotate/logrotate.status", // Fedora, RHEL
	}
)

// There is no DefaultSecretsGroup: it defaults to the keeper's own primary
// group, so the only account that can read the ciphertext is the one that
// decrypts it, by construction rather than by a membership list.

// BrokerMaxMemoryPercent is the share of the machine the broker may hold. The
// same share the executor's cgroup gets, for the same reason: it is the number
// above which one part of faramir is taking the host rather than using it.
//
// A value costs roughly 15 KB of the broker's memory per byte of secret, so a
// store that has grown is what reaches this, not a broker misbehaving. The
// other half is internal/redact.MaxValueBytes: one value cannot get there on
// its own.
const BrokerMaxMemoryPercent = 25

// Layout is everything the templates and the install steps must agree on, built
// once by Options.layout and passed down.
type Layout struct {
	// ClientGroup does two jobs. It is the broker socket's SocketGroup and what
	// [server] allowed_group names, so its members reach the broker; and it
	// group-owns an enrolled tree, so the broker can stat a request's cwd and the
	// executor can run there. The operator is in it for the first, the broker
	// and the executor for the second, and the keeper for neither. The executor
	// therefore reaches the broker socket, which is argued in
	// faramir-exec.service.tmpl.
	//
	// SecretsGroup owns the secrets directory and holds the keeper alone, that
	// being the only account that opens a managed file; the operator is not in
	// it, so editing a managed file needs sudo. One group for both would let
	// every caller that can ask for a value by name read the file it comes from.
	// Defaults to KeeperUser; --secrets-group names another, which adds a second
	// reader.
	ClientGroup  string
	SecretsGroup string
	BrokerUser   string
	KeeperUser   string
	ExecUser     string
	// ExecGroup, BrokerGroup and KeeperGroup are the service accounts' own groups,
	// resolved from those accounts at install time rather than assumed to share
	// their names: --broker-user and friends may adopt an account whose primary
	// group is called something else.
	//
	// ExecGroup renders into [ssh] exec_group, the group the agent relay's
	// SO_PEERCRED check admits and the group its socket is handed to.
	// BrokerGroup is the keeper and executor sockets' SocketGroup=, which is what
	// lets the broker reach them and nothing else reach them at all.
	ExecGroup   string
	BrokerGroup string
	KeeperGroup string

	ConfigDir  string
	ConfigFile string
	BinDir     string
	LibexecDir string
	DocDir     string
	RunDir     string
	LogDir     string

	AgeKeyPath string
	// SshAgent and SshAdd are the binaries the broker execs, resolved on PATH at
	// install time. The broker runs them as the uid holding every plaintext
	// value, so which binary they are is init's to decide.
	SshAgent string
	SshAdd   string
	// SSHKey is the identity the broker lends to brokered commands. It renders
	// into config.toml's [ssh] key, so the flag and the file cannot drift apart.
	//
	// Never empty: one is minted whether or not a host turns out to need it, so
	// `init` prints a public half the operator can add to an authorized_keys.
	// The cost is an ssh-agent holding a key that may open nothing.
	//
	// It defaults beside the age key in the config directory, which is outside
	// the broker's ReadWritePaths, so the account that uses the key is not the
	// account that can replace it. Named id_ed25519, a name the deny patterns
	// refuse wherever it turns up rather than only under ConfigDir.
	SSHKey string

	// Links is the [[secret.link]] entries, read off the config rather than given
	// by a flag. They render back into config.toml, so init asserts them, and
	// the grant they need, on every run. One field for both jobs: the entries
	// config.toml carries, and the paths the deny rules refuse.
	//
	// The account-wide lists only. A linked file is one operator's own, so
	// putting it in the per-project assets would change every enrolled tree
	// whenever a link was added. Pi has no account-wide file, so its extension
	// does not carry these.
	Links []config.Link

	// Blocked is the [[secret.block]] entries, read off the config the same way
	// and rendering into the same deny rules. Separate from Links because that
	// is the whole difference between them: these paths are refused to the
	// agent and never read, so no grant is asked for and no value is held.
	Blocked []config.BlockedPath

	// The tunables. Each is set by a flag, rendered into config.toml, and read
	// back out of it on the next run, so a flag left out keeps what the install
	// already has rather than reverting to the compiled-in value. A value that
	// reaches the file and is recoverable from nothing would be erased by the
	// next command that rewrites it.
	CommandEnv map[string]string
	// AgentUser is the account the coding agent runs as, which is the operator.
	// Named in the sudo environment so a command that reaches root through the
	// broker can still resolve whose host it is on: sudo sets SUDO_USER from the
	// executor account, which is nobody's home and nobody's identity.
	AgentUser            string
	CommandTimeoutSec    int
	CommandMaxTimeoutSec int
	CommandConcurrency   int
	// CommandMaxMemoryPercent renders into the executor unit's MemoryMax and
	// CommandMaxProcessMemoryMB into its LimitDATA. The second is the bound and
	// the first the backstop: a runaway is one process asking for far more than
	// a real one, which LimitDATA refuses, and fan-out is many processes each
	// asking for a little, which only a cgroup total sees.
	CommandMaxMemoryPercent   int
	CommandMaxProcessMemoryMB int
	// BrokerMaxMemoryPercent renders into the broker unit's MemoryMax. A
	// constant rather than a key, and a share of the machine rather than a
	// number of bytes: what the broker holds is the value set, whose cost is
	// the operator's to control, and a fixed ceiling that fits one host is
	// wrong on the next.
	//
	// It bounds nothing the operator wants; what it decides is who dies when
	// the value set outgrows the machine. Without it the host's OOM killer
	// chooses, and it may not choose the broker. `faramir doctor` reports what
	// the broker is using against this, so a store growing towards it is seen
	// before it is met.
	BrokerMaxMemoryPercent int
	SudoTimeoutSec         int
	SecretMinLength        int

	// AllowSudo is the switch for the whole arrangement: unset renders no
	// [sudo] section, writes no sudoers file and no PAM service, so nothing
	// can be asked for.
	AllowSudo bool

	// SudoRs says which sudo will read what this install writes. Both
	// implementations read /etc/sudoers.d and they take different settings, so
	// the grant, the PAM service and the question of whether a shared stack is
	// edited at all are rendered for the one /usr/bin/sudo resolves to. Probed at
	// install time rather than configured: it follows the `sudo` alternatives
	// group, which an operator changes without telling faramir.
	SudoRs bool

	// NotifyCommand announces that a question is waiting. Empty is the default
	// and means `faramir sudo watch` is the only place one shows up.
	// Written by init, as pam_service and helper are: the broker execs this as
	// the uid holding every plaintext value.
	NotifyCommand []string

	// NotifyAdopted says the argv above was read back off the installed config
	// rather than named on this run, which is what a refusal has to say: an
	// operator who typed no flag is being told about a value they last set on
	// another run, and one told to fix "--notify-command" would look for a flag
	// that is not in their command line. Unexported: nothing renders it.
	NotifyAdopted bool
}

// PamHelper is what the PAM service execs, as root, to decide one sudo: a
// wrapper beside the hook's own files that runs `faramir pam-escalate`.
func (l Layout) PamHelper() string { return filepath.Join(l.LibexecDir, "pam-escalate") }

// PamService is the sudoers `pam_service` name, and so the file under
// /etc/pam.d that sudo reads for the executor's account alone.
func (l Layout) PamService() string { return PamServiceName }

// PamFile is where that service lives.
func (l Layout) PamFile() string { return PamServiceFile }

// SudoPamStacks is the stacks every account's sudo reads. faramir writes a
// delimited block into these only where the host's sudo is sudo-rs, which has no
// pam_service and so reaches no service a caller may name. Two of them because
// the service name is the launch type: `sudo` for a command, `sudo-i` for a login
// shell, and an arrangement covering one is one that fails on the other.
//
// A function rather than a variable: pamDir is redirected by tests, and a list
// built at package init would keep pointing at /etc.
func SudoPamStacks() []string { return []string{PamDir + "/sudo", PamDir + "/sudo-i"} }

// PamStack is the file that carries the stack a brokered command's sudo
// authenticates against on this host: faramir's own service where sudo can be
// sent to one by name, and the shared stack it reads for every account where it
// cannot. Rendered into [sudo] pam_stack, so nothing downstream has to
// work out which arrangement an install made.
func (l Layout) PamStack() string {
	if l.SudoRs {
		return l.SudoPamFile()
	}
	return l.PamFile()
}

// SudoPamFile is the command's stack, named by the templates so they can say
// what faramir does and does not touch there.
func (l Layout) SudoPamFile() string { return SudoPamStacks()[0] }

// SudoPamFiles is every shared stack the block goes into.
func (l Layout) SudoPamFiles() []string { return SudoPamStacks() }

// SudoEnvFile is what a brokered command's sudo hands root on top of what sudo
// builds, read by the pam_env line in faramir's own PAM service. Beside the
// other files this install renders for its own use, and so with the hook that
// reads them: not under /etc/sudoers.d, which sudo parses in its entirety, and
// not under the config directory, which an uninstall keeps and so must never
// remove wholesale. Nowhere the executor's uid can write either, since PAM reads
// it as root and a file that uid could rewrite would be that uid choosing root's
// environment.
func (l Layout) SudoEnvFile() string { return filepath.Join(l.LibexecDir, "sudo-env") }

// SudoersFile is the grant itself. Under /etc/sudoers.d rather than in the
// config directory: sudo reads one place, and a grant kept where --config-dir
// points would be a grant sudo never saw.
func (l Layout) SudoersFile() string { return SudoersFile }

// AgeKeyDir is where the key lives, which is the config directory: the key
// follows the config, so secrets in an encrypted home have the key that opens
// them in there too.
func (l Layout) AgeKeyDir() string { return filepath.Dir(l.AgeKeyPath) }

// SecretsDir is where the managed sops files live, always under the config
// directory, so the ciphertext cannot end up on a different disk from the key
// that opens it.
func (l Layout) SecretsDir() string { return filepath.Join(l.ConfigDir, "secrets") }

// SopsConfigPath is where the creation rule lives: the config directory, beside
// the other files that decide how the secrets are treated, rather than inside
// the directory it governs. See stepSopsConfig for why not.
func (l Layout) SopsConfigPath() string { return filepath.Join(l.ConfigDir, ".sops.yaml") }

// AuditLogPath is the file the broker appends a record to. Rendered into both
// config.toml and logrotate.conf from LogDir, and created by the install so
// that its owner is not whichever uid writes to it first.
func (l Layout) AuditLogPath() string { return filepath.Join(l.LogDir, "audit.log") }

// BrokerHome, KeeperHome and ExecHome are the service accounts' homes, derived
// from the account names so that renaming one does not leave it living in a
// directory named after the old one. Each unit's StateDirectory= renders from
// the same value.
func (l Layout) BrokerHome() string { return "/var/lib/" + l.BrokerUser }

func (l Layout) KeeperHome() string { return "/var/lib/" + l.KeeperUser }

func (l Layout) ExecHome() string { return "/var/lib/" + l.ExecUser }

// ExecKnownHosts is where --known-hosts pins the host keys a brokered ssh
// verifies against. Under the executor's own home rather than
// /etc/ssh/ssh_known_hosts: ssh reads the global file first and this second, so
// pinning here adds to what the host already trusts instead of rewriting a file
// every other account on it reads.
func (l Layout) ExecKnownHosts() string {
	return filepath.Join(l.ExecHome(), ".ssh", "known_hosts")
}

// KeeperBinds is what has to be bound back into the keeper's mount namespace,
// already formatted as BindReadOnlyPaths= values.
//
// The keeper holds the age key, so it runs with the homes taken away entirely.
// A config directory kept in one is then absent rather than unreadable, so
// ProtectHome drops to tmpfs and that one directory is bound back while every
// other home stays invisible. One entry at most, the secrets directory and the
// key both being inside it. Empty when the config sits outside the homes,
// which is the case to prefer.
func (l Layout) KeeperBinds() []string {
	if HomeOf(l.ConfigDir) == "" {
		return nil
	}
	return []string{l.ConfigDir}
}

// HomeOf returns the home directory a path sits in, or empty when it sits
// outside every home. Matched on the path rather than by looking accounts up:
// what decides this is what the keeper's ProtectHome= hides, which is /root and
// everything directly under /home.
func HomeOf(path string) string {
	switch {
	case path == "/root" || strings.HasPrefix(path, "/root/"):
		return "/root"
	case strings.HasPrefix(path, "/home/"):
		rest := strings.TrimPrefix(path, "/home/")
		name, _, _ := strings.Cut(rest, "/")
		if name == "" {
			return ""
		}
		return "/home/" + name
	}
	return ""
}
