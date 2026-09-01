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
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/hostfs"
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

// StaleSopsConfigPath is where earlier installs put the creation rule, named so
// doctor can report one left behind: sops takes the nearest walking up from the
// working directory, so a copy inside the secrets directory shadows the current
// one for anything run from in there.
func (l Layout) StaleSopsConfigPath() string { return filepath.Join(l.SecretsDir(), ".sops.yaml") }

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
func (l Layout) ExecHome() string   { return "/var/lib/" + l.ExecUser }

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

// Validate rejects the placements that install cleanly and then do not work,
// before anything is written.
func (l Layout) Validate() error {
	// The secrets and the key are under it, so checking the config directory
	// checks every path an operator can move.
	dir := l.ConfigDir
	if !filepath.IsAbs(dir) {
		return fmt.Errorf("config dir must be an absolute path: %s", dir)
	}
	// systemd word-splits Environment= and expands % specifiers in it, so a path
	// holding either reaches the daemons truncated or not at all.
	if strings.ContainsAny(dir, " \t") {
		return fmt.Errorf("config dir must not contain whitespace: %s", dir)
	}
	if strings.Contains(dir, "%") {
		return fmt.Errorf("config dir must not contain '%%': %s", dir)
	}
	if under := privateTmpDir(dir); under != "" {
		return fmt.Errorf("config dir must not be under %s: %s\n"+
			"Every unit runs with PrivateTmp=true, so each daemon gets a %s of its "+
			"own and none of them would find what this run wrote. The install would "+
			"finish and the host would serve nothing. Name a directory outside it, "+
			"%s being the default", under, dir, under, DefaultConfigDir)
	}
	// Blocked here rather than left to whatever renders it: these paths are
	// interpolated into the agents' JSON settings, into config.toml and into the
	// deny patterns, and each format escapes a different set. A settings file the
	// agent cannot parse reads as an enrolment that worked with every rule in it
	// missing.
	if name, bad := hasControlChar(dir); bad {
		return fmt.Errorf("config dir must not contain a control character (%s): %q",
			name, dir)
	}
	if name, bad := hasControlChar(l.SSHKey); bad {
		return fmt.Errorf("ssh key path must not contain a control character (%s): %q",
			name, l.SSHKey)
	}
	for name, account := range map[string]string{
		"group":         l.ClientGroup,
		"broker user":   l.BrokerUser,
		"keeper user":   l.KeeperUser,
		"exec user":     l.ExecUser,
		"agent user":    l.AgentUser,
		"secrets group": l.SecretsGroup,
	} {
		// The agent user and the secrets group are named after the rest because
		// they are rendered later, not because they are checked less: both reach
		// config.toml, and the agent user reaches the environment file a brokered
		// command's sudo is given.
		if account == "" && (name == "agent user" || name == "secrets group") {
			continue // filled in by the step that resolves it, or not used
		}
		if account == "" {
			return fmt.Errorf("%s must be named", name)
		}
		if strings.ContainsAny(account, " \t:,") {
			return fmt.Errorf("%s is not a usable account name: %q", name, account)
		}
		// Every one of these is written into a file that is read a line at a time:
		// config.toml, the logrotate rule, and the environment file pam_env hands
		// to a brokered command's sudo. A newline in a name ends the line it was
		// written into and makes the rest of it a directive of its own, in a file
		// that decides what root is given.
		if bad, found := hasControlChar(account); found {
			return fmt.Errorf("%s must not contain a control character (%s): %q",
				name, bad, account)
		}
	}
	// The three uids are the boundaries: two of them sharing a name is an install
	// where the executor's uid holds the age key or the audit log.
	seen := map[string]string{}
	for name, account := range map[string]string{
		"broker user": l.BrokerUser,
		"keeper user": l.KeeperUser,
		"exec user":   l.ExecUser,
	} {
		if other, dup := seen[account]; dup {
			return fmt.Errorf("%s and %s are both %q: the three uids are the "+
				"boundary between the age key, the audit log and the commands "+
				"the broker runs, and sharing one removes it", other, name, account)
		}
		seen[account] = name
	}
	// And the operator is not one of them. Separate from the loop above, which is
	// about the three daemons keeping their boundary from each other: this is
	// about the boundary that makes the whole arrangement work, a brokered command
	// running as an account holding nothing the agent's account holds. An operator
	// who is also a daemon leaves none of it, every injected value sitting in a
	// process of the operator's own uid and every path refused to the agent being
	// that account's to read.
	//
	// Empty is left alone here as it is above, the step that resolves it not
	// having run on every path that builds a layout.
	if l.AgentUser != "" {
		for _, daemon := range []struct{ role, flag, account string }{
			{"broker", BrokerUserFlag, l.BrokerUser},
			{"keeper", KeeperUserFlag, l.KeeperUser},
			{"executor", ExecUserFlag, l.ExecUser},
		} {
			if l.AgentUser == daemon.account {
				return fmt.Errorf("--agent-user %s is the account the %s runs as, so the "+
					"operator and that daemon would be one uid and nothing a brokered "+
					"command holds would be out of the agent's reach. Name a different "+
					"account, or move the daemon with %s",
					l.AgentUser, daemon.role, daemon.flag)
			}
		}
	}
	return l.validateNotifyCommand()
}

// PrivateTmp is what PrivateTmp= gives every unit its own copy of. Both
// hierarchies, since the directive covers both.
//
// A variable rather than a constant for this package's own tests, which point
// an install at a directory made by t.TempDir(): that lands under TMPDIR, which
// is the very thing this refuses on a real host, so a test asserting on some
// other refusal would meet this one first. Unexported and cleared only by the
// helper those tests share, so nothing outside can turn the check off.
var PrivateTmp = []string{"/tmp", "/var/tmp"}

// privateTmpDir is the temporary hierarchy a path sits in, or "" for a path
// outside both.
//
// Refused rather than left to fail at the daemons' next start. PrivateTmp=true
// gives every unit a /tmp and a /var/tmp of its own, so a config directory
// there is written by an install running in the host's namespace and looked for
// by three daemons that each have a different one. What the operator sees is an
// install reporting every step done and a broker that will not start, with the
// directory sitting on disk exactly where they put it.
//
// Both hierarchies, since PrivateTmp= covers both. The check is on the path
// rather than on the filesystem under it: a bind mount elsewhere is somebody's
// deliberate arrangement, and what breaks the install is the unit directive
// reading these two names.
func privateTmpDir(dir string) string {
	for _, tmp := range PrivateTmp {
		if dir == tmp || strings.HasPrefix(dir, tmp+"/") {
			return tmp
		}
	}
	return ""
}

// hasControlChar reports whether a path holds a character no rendered format
// takes literally, naming it so the refusal says which. DEL as well as the C0
// range, and an invalid UTF-8 byte with them: ranging over a string yields
// U+FFFD for one, which is not what the operator typed.
func hasControlChar(text string) (string, bool) {
	for _, r := range text {
		switch {
		case r == utf8.RuneError:
			return "an invalid UTF-8 byte", true
		case r < 0x20 || r == 0x7f:
			return fmt.Sprintf("U+%04X", r), true
		}
	}
	return "", false
}

// notifySource names where the announcement being validated came from, so a
// refusal points at what the operator would change: the flag when they typed
// one, and the installed config when this run kept what was already there. Both
// refusals name the flag as the way to change it either way.
func (l Layout) notifySource() string {
	if l.NotifyAdopted {
		return "the installed [sudo] notify_command"
	}
	return "--notify-command"
}

// validateNotifyCommand holds the announcement to what the loader will accept,
// so a bad one is refused before anything is written rather than at the
// daemon's next start. The rules are the loader's: see
// config.loadSudo.
func (l Layout) validateNotifyCommand() error {
	if len(l.NotifyCommand) == 0 {
		return nil
	}
	if !l.AllowSudo {
		return fmt.Errorf("--notify-command announces a pending escalation, and this "+
			"install grants none: pass --allow-sudo as well, or drop it. Without the "+
			"grant no [sudo] section is written and there is nothing to announce (%s)",
			strings.Join(l.NotifyCommand, " "))
	}
	if !slices.ContainsFunc(l.NotifyCommand, func(arg string) bool {
		return strings.Contains(arg, "{prompt}") || strings.Contains(arg, "{id}")
	}) {
		return fmt.Errorf("%s names neither {prompt} nor {id}, so it "+
			"would announce that something is waiting without saying what: %s",
			l.notifySource(), strings.Join(l.NotifyCommand, " "))
	}
	// Absolute by the time this runs, Options.layout resolving argv[0] on PATH.
	// Checked rather than assumed: a name that resolved to nothing would reach
	// the config as itself and be looked up again by the broker's PATH.
	if !filepath.IsAbs(l.NotifyCommand[0]) {
		return fmt.Errorf("%s %q is not on PATH and is not an absolute "+
			"path: it is run as the account holding every decrypted value, so which "+
			"file it reaches is the install's to decide rather than the broker's PATH's",
			l.notifySource(), l.NotifyCommand[0])
	}
	// And it has to be there: a path written out by hand is taken as given, so a
	// typo would reach the config and fail at the --check that follows, after
	// every file was written.
	info, err := os.Stat(l.NotifyCommand[0])
	if err != nil {
		return fmt.Errorf("%s %q is not there (%v): install it, or name "+
			"a program that exists with --notify-command. It announces a pending "+
			"escalation, so an install that wrote it would come up with nothing "+
			"announcing anything", l.notifySource(), l.NotifyCommand[0], err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("%s %q is not an executable file: the broker "+
			"execs it directly rather than through a shell",
			l.notifySource(), l.NotifyCommand[0])
	}
	return nil
}

// HomeIsMounted reports whether an encrypted home has been unlocked. Writing
// into one before its owner logs in lands in the unencrypted backing directory,
// where it is shadowed the moment the home mounts. A mounted filesystem sits
// on a different device from the directory it covers, which is what this
// compares; mountpoint(1) is not on every host, and its absence would read as
// "not mounted".
func HomeIsMounted(home string) bool {
	info, err := os.Stat(home)
	if err != nil {
		return false
	}
	parent, err := os.Stat(filepath.Dir(home))
	if err != nil {
		return false
	}
	return hostfs.DeviceOf(info) != hostfs.DeviceOf(parent)
}

// LooksEncrypted reports whether a home is one of the ecryptfs layouts, which
// are the ones that are a different directory before login.
func LooksEncrypted(home string) bool {
	if _, err := os.Stat(filepath.Join("/home/.ecryptfs", filepath.Base(home))); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(home, ".ecryptfs"))
	return err == nil
}
