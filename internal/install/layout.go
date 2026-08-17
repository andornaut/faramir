// Package install provisions a host: accounts, directories, the age key, the
// binaries, the systemd units, and the checks that say whether what landed
// works.
//
// A package rather than shell scripts because the same values (the shared
// group, the service uids) have to reach several files that must agree.  All
// of them render from one Layout.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/config"
)

// Default paths.  Only ConfigDir is meant to be moved; the rest are here so the
// templates have one source for them.
const (
	DefaultConfigDir  = "/etc/faramir"
	DefaultBinDir     = "/usr/local/bin"
	DefaultLibexecDir = "/usr/local/libexec/faramir"
	DefaultDocDir     = "/usr/local/share/doc/faramir"
	DefaultRunDir     = "/run/faramir"
	DefaultLogDir     = "/var/log/faramir"

	// Not derived from a layout field: the path is the distribution's.
	pamServiceName = "faramir-sudo"

	DefaultClientGroup = "dev"
	DefaultBrokerUser  = "faramir-broker"
	DefaultKeeperUser  = "faramir-keeper"
	DefaultExecUser    = "faramir-exec"
)

// Where the distribution keeps the two files a sudo grant needs, the audit
// log's rotation rule, and logrotate's own record of what it has rotated.
// Variables rather than constants so a test can point at files it wrote: what
// has to be exercised is a host that has one and not the other, which is a
// state no test can create at the real paths.
var (
	sudoersDir      = "/etc/sudoers.d"
	pamDir          = "/etc/pam.d"
	sudoersFile     = sudoersDir + "/faramir"
	pamServiceFile  = pamDir + "/" + pamServiceName
	logrotateConfig = "/etc/logrotate.d/faramir"

	// The state path is compiled into logrotate rather than configured, and
	// distributions do not agree on it, so each one they use is looked for and
	// the first that exists answers.
	logrotateStatePaths = []string{
		"/var/lib/logrotate/status",           // Debian, Ubuntu
		"/var/lib/logrotate.status",           // older Debian
		"/var/lib/logrotate/logrotate.status", // Fedora, RHEL
	}
)

// There is no DefaultSecretsGroup: it defaults to the keeper's own primary
// group, so the only account that can read the ciphertext is the one that
// decrypts it, by construction rather than by a membership list.

// Layout is everything the templates and the install steps must agree on. Built
// once by Options.layout and passed down.
type Layout struct {
	// ClientGroup does two jobs, which is why one name covers accounts that are
	// not clients of anything.  It is the broker socket's SocketGroup and what
	// [server] allowed_group names, so its members reach the broker; and it
	// group-owns an enrolled tree, so the broker can stat a request's cwd and the
	// executor can run there.  The operator is in it for the first, the broker and
	// the executor for the second, and the keeper for neither.
	//
	// The executor therefore reaches the broker socket, which is deliberate and
	// argued where it shows: see faramir-exec.service.tmpl.
	//
	// SecretsGroup owns the secrets directory and holds the keeper alone, that
	// being the only account that opens a managed file; the operator is not in it,
	// so editing a managed file needs sudo.  One group for both would let every
	// caller that can ask for a value by name read and replace the file it comes
	// from.  Defaults to KeeperUser; --secrets-group names another, which adds a
	// second reader.
	ClientGroup  string
	SecretsGroup string
	BrokerUser   string
	KeeperUser   string
	ExecUser     string
	// ExecGroup, BrokerGroup and KeeperGroup are the service accounts' own
	// groups, resolved from those accounts at install time rather than assumed to
	// share their names: --broker-user and friends may adopt an account whose
	// primary group is called something else, and a directive naming the wrong one
	// joins some other group or none.
	//
	// ExecGroup renders into [ssh] exec_group, the group the agent relay's
	// SO_PEERCRED check admits and the group its socket is handed to.  BrokerGroup
	// is the keeper and executor sockets' SocketGroup=, which is what lets the
	// broker reach them and nothing else reach them at all.
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
	// install time rather than assumed to sit in /usr/bin.  The broker runs them
	// as the uid holding every plaintext value, so which binary they are is init's
	// to decide and not a drop-in's.
	SshAgent string
	SshAdd   string
	// SSHKey is the identity the broker lends to brokered commands.  It renders
	// into config.toml's [ssh] key, which is why it is here and not only on
	// Options: the config is written from this struct on every run, so the flag
	// and the file cannot drift apart.
	//
	// Never empty.  One is minted whether or not a host turns out to need it, so
	// `init` prints a public half the operator can add to an authorized_keys
	// without re-running with a flag.  The cost is an ssh-agent holding a key
	// that may open nothing.
	//
	// It defaults beside the age key in the config directory, and is read-only
	// there: the broker runs ProtectSystem=strict with the config directory
	// outside its ReadWritePaths, so the account that uses the key is not the
	// account that can replace it.
	//
	// Named id_ed25519 because the deny patterns already refuse that name by name,
	// so a copy of it is refused wherever it turns up, not only where ConfigDir
	// was rendered into a pattern.
	SSHKey string

	// Links is the [[secret.link]] entries, read off the config rather than given
	// by a flag.  They render back into config.toml, which is what makes them
	// install state rather than a drop-in's: init asserts them, and the grant they
	// need, on every run.
	//
	// One field for both jobs: the entries config.toml carries, and the paths the
	// deny rules refuse.  They were separate while a drop-in could declare a link
	// the base file must not re-render; with one config file there is no such
	// entry and no such distinction.
	//
	// The account-wide lists only.  A linked file is one host's operator's own, so
	// putting it in the per-project assets would change every enrolled tree's
	// files whenever a link was added, and report drift in all of them until each
	// was enrolled again.  Pi has no account-wide file, so its extension does not
	// carry these; that is the same gap it already has.
	Links []config.Link

	// The tunables.  Each is set by a flag, rendered into config.toml, and read
	// back out of it on the next run, so a flag left out keeps what the install
	// already has rather than reverting to the compiled-in value.  That round
	// trip is what TestALinkOperationRendersTheSameConfigTheInstallDid holds to:
	// a value that reaches this file and is recoverable from nothing would be
	// erased by the next command that rewrites it.
	CommandEnv           map[string]string
	CommandTimeoutSec    int
	CommandMaxTimeoutSec int
	CommandConcurrency   int
	ApprovalTimeoutSec   int
	SecretMinLength      int
	SecretMinRefreshSec  int

	// AllowSudo is the switch for the whole arrangement: unset renders no [approval]
	// section, writes no sudoers file and no PAM service, so nothing can be asked
	// for.
	AllowSudo bool

	// NotifyCommand announces that a question is waiting.  Empty is the default
	// and means `faramir approvals --watch` is the only place one shows up.
	//
	// Written by init rather than left to a drop-in, and the reason is the same
	// one that owns pam_service and helper: the broker execs this as the uid
	// holding every plaintext value, so a file another account could write would
	// be choosing what that uid runs.  Being init's, it needs a flag, or the
	// ownership only says where it cannot be set.
	NotifyCommand []string
}

// PamHelper is what the PAM service execs, as root, to decide one sudo: a
// wrapper beside the hook's own files that runs `faramir pam-approve`.
func (l Layout) PamHelper() string { return filepath.Join(l.LibexecDir, "pam-approve") }

// PamService is the sudoers `pam_service` name, and so the file under
// /etc/pam.d that sudo reads for the executor's account alone.
func (l Layout) PamService() string { return pamServiceName }

// PamFile is where that service lives.
func (l Layout) PamFile() string { return pamServiceFile }

// SudoersFile is the grant itself.  Under /etc/sudoers.d rather than in the
// config directory: sudo reads one place, and a grant kept where --config-dir
// points would be a grant sudo never saw.
func (l Layout) SudoersFile() string { return sudoersFile }

// AgeKeyDir is where the key lives, which is the config directory: the key
// follows the config, so secrets in an encrypted home have the key that opens
// them in there too.
func (l Layout) AgeKeyDir() string { return filepath.Dir(l.AgeKeyPath) }

// SecretsDir is where the managed sops files live, always under the config
// directory rather than anywhere an operator names, so the ciphertext cannot
// end up on a different disk from the key that opens it.
func (l Layout) SecretsDir() string { return filepath.Join(l.ConfigDir, "secrets") }

// SopsConfigPath is where the creation rule lives: the config directory, beside
// the other files that decide how the secrets are treated, rather than inside
// the directory it governs.  See stepSopsConfig for why not.
func (l Layout) SopsConfigPath() string { return filepath.Join(l.ConfigDir, ".sops.yaml") }

// StaleSopsConfigPath is where earlier installs put the creation rule.  Named
// so doctor can report one left behind: sops takes the nearest walking up from
// the working directory, so a copy inside the secrets directory shadows the
// current one for anything run from in there.
func (l Layout) StaleSopsConfigPath() string { return filepath.Join(l.SecretsDir(), ".sops.yaml") }

// AuditLogPath is the file the broker appends a record to.  Rendered into both
// config.toml and logrotate.conf from LogDir, and created by the install so
// that its owner is not whichever uid writes to it first.
func (l Layout) AuditLogPath() string { return filepath.Join(l.LogDir, "audit.log") }

// BrokerHome, KeeperHome and ExecHome are the service accounts' homes.  Derived
// from the account names so that renaming one does not leave it living in a
// directory named after the old one, which is also what StateDirectory= in each
// unit is rendered with.
func (l Layout) BrokerHome() string { return "/var/lib/" + l.BrokerUser }
func (l Layout) KeeperHome() string { return "/var/lib/" + l.KeeperUser }
func (l Layout) ExecHome() string   { return "/var/lib/" + l.ExecUser }

// ExecKnownHosts is where --known-hosts pins the host keys a brokered ssh
// verifies against.  Under the executor's own home rather than
// /etc/ssh/ssh_known_hosts: ssh reads the global file first and this second, so
// pinning here adds to what the host already trusts instead of rewriting a file
// every other account on it reads.
func (l Layout) ExecKnownHosts() string {
	return filepath.Join(l.ExecHome(), ".ssh", "known_hosts")
}

// KeeperBinds is what has to be bound back into the keeper's mount namespace,
// already formatted as BindReadOnlyPaths= values.
//
// The keeper is the uid that holds the age key, so it runs with the homes taken
// away entirely.  A config directory kept in one is then not merely unreadable
// but absent, so ProtectHome drops to tmpfs and that one directory is bound
// back: every other home stays invisible.  One entry at most, the secrets
// directory and the key both being inside it.
//
// Empty when the config sits outside the homes, which is the case
// ProtectHome=true covers and the one to prefer.
func (l Layout) KeeperBinds() []string {
	if homeOf(l.ConfigDir) == "" {
		return nil
	}
	return []string{l.ConfigDir}
}

// homeOf returns the home directory a path sits in, or empty when it sits
// outside every home.  Matched on the path rather than by looking accounts up,
// because what decides this is the keeper's ProtectHome=, and that is what
// systemd hides: /root and everything directly under /home.
func homeOf(path string) string {
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

// validate rejects the placements that install cleanly and then do not work.
// Checked before anything is written, so a bad value stops the run rather than
// surfacing as a mount error once the binaries are already on the host.
func (l Layout) validate() error {
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
	// Refused here rather than left to whatever renders it.  These paths are
	// interpolated into the agents' JSON settings, into config.toml and into the
	// deny patterns, and each of those formats escapes a different set: a
	// renderer that got it wrong would write a settings file the agent cannot
	// parse, which reads as an enrolment that worked with every rule in it
	// missing.  One check on the way in beats three on the way out.
	if name, bad := hasControlChar(dir); bad {
		return fmt.Errorf("config dir must not contain a control character (%s): %q",
			name, dir)
	}
	if name, bad := hasControlChar(l.SSHKey); bad {
		return fmt.Errorf("ssh key path must not contain a control character (%s): %q",
			name, l.SSHKey)
	}
	for name, account := range map[string]string{
		"group":       l.ClientGroup,
		"broker user": l.BrokerUser,
		"keeper user": l.KeeperUser,
		"exec user":   l.ExecUser,
	} {
		if account == "" {
			return fmt.Errorf("%s must be named", name)
		}
		if strings.ContainsAny(account, " \t:,") {
			return fmt.Errorf("%s is not a usable account name: %q", name, account)
		}
	}
	// The three uids are the boundaries.  Two of them sharing a name is not a
	// tighter install, it is one where the executor's uid holds the age key or the
	// audit log, which is the whole thing this project is for.
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
	return l.validateNotifyCommand()
}

// hasControlChar reports whether a path holds a character no rendered format
// takes literally, naming it so the refusal says which.  DEL as well as the C0
// range, and an invalid UTF-8 byte with them: ranging over a string yields
// U+FFFD for one, which is not what the operator typed and not what any later
// comparison against the path would match.
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

// validateNotifyCommand holds the announcement to what the loader will accept,
// so a bad one is refused before anything is written rather than at the daemon's
// next start.  The rules are the loader's, restated here because init is the
// only writer: see config.parseSudo.
func (l Layout) validateNotifyCommand() error {
	if len(l.NotifyCommand) == 0 {
		return nil
	}
	if !l.AllowSudo {
		return fmt.Errorf("--notify-command announces a pending approval, and this "+
			"install grants none: pass --allow-sudo as well, or drop it. Without the "+
			"grant no [approval] section is written and there is nothing to announce (%s)",
			strings.Join(l.NotifyCommand, " "))
	}
	if !slices.ContainsFunc(l.NotifyCommand, func(arg string) bool {
		return strings.Contains(arg, "{prompt}") || strings.Contains(arg, "{id}")
	}) {
		return fmt.Errorf("--notify-command names neither {prompt} nor {id}, so it "+
			"would announce that something is waiting without saying what: %s",
			strings.Join(l.NotifyCommand, " "))
	}
	// Absolute by the time this runs: Options.layout resolves argv[0] on PATH, as
	// it does ssh_agent and ssh_add and for the same reason.  Checked rather than
	// assumed, a name that resolved to nothing otherwise reaching the config as
	// itself and being looked up again later, by the broker's PATH rather than
	// the install's.
	if !filepath.IsAbs(l.NotifyCommand[0]) {
		return fmt.Errorf("--notify-command %q is not on PATH and is not an absolute "+
			"path: it is run as the account holding every decrypted value, so which "+
			"file it reaches is the install's to decide rather than the broker's PATH's",
			l.NotifyCommand[0])
	}
	// And it has to be there.  Absolute is not the same question as present: a
	// path resolves on PATH or it does not, but one written out by hand is taken
	// as given, so `--notify-command /usr/bin/wal` would otherwise reach the
	// config and fail at the --check that follows, after every file was written.
	// One typo, two spellings, and they must be refused alike.
	info, err := os.Stat(l.NotifyCommand[0])
	if err != nil {
		return fmt.Errorf("--notify-command %q is not there (%v): install it, or name "+
			"a program that exists. It announces a pending approval, so an install "+
			"that wrote it would come up with nothing announcing anything",
			l.NotifyCommand[0], err)
	}
	if info.IsDir() || info.Mode().Perm()&0o111 == 0 {
		return fmt.Errorf("--notify-command %q is not an executable file: the broker "+
			"execs it directly rather than through a shell", l.NotifyCommand[0])
	}
	return nil
}

// homeIsMounted reports whether an encrypted home has been unlocked.
//
// Writing into one before its owner logs in lands in the unencrypted backing
// directory, where it is shadowed and invisible the moment the home mounts:
// the install looks like it worked and the daemons never see the file again.  A
// mounted filesystem sits on a different device from the directory it covers,
// which is what this compares; mountpoint(1) is not on every host and its
// absence would read as "not mounted".
func homeIsMounted(home string) bool {
	info, err := os.Stat(home)
	if err != nil {
		return false
	}
	parent, err := os.Stat(filepath.Dir(home))
	if err != nil {
		return false
	}
	return deviceOf(info) != deviceOf(parent)
}

// looksEncrypted reports whether a home is one of the ecryptfs layouts, which
// are the ones that are a different directory before login.
func looksEncrypted(home string) bool {
	if _, err := os.Stat(filepath.Join("/home/.ecryptfs", filepath.Base(home))); err == nil {
		return true
	}
	_, err := os.Stat(filepath.Join(home, ".ecryptfs"))
	return err == nil
}
