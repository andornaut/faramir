// Package install provisions a host: accounts, directories, the age key, the
// binaries, the systemd units, and the checks that say whether what landed
// actually works.
//
// It exists as a package rather than a set of shell scripts because the same
// values have to reach several files that must agree.  The shared group is
// named in the config the sockets check and in the units that reach the working
// tree; the service uids are named in both as well.  A script per phase makes
// each of those an environment variable a caller can get wrong in one place and
// not another, and the symptom is a broker that installs cleanly, starts, and
// refuses every connection.  Rendering all of them from one Layout removes the
// question.
package install

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
)

// Default paths.  Only ConfigDir and SecretsDir are meant to be moved; the rest
// are where a system daemon's files belong and are here so the templates have
// one source for them rather than a literal each.
const (
	DefaultConfigDir  = "/etc/faramir"
	DefaultBinDir     = "/usr/local/bin"
	DefaultLibexecDir = "/usr/local/libexec/faramir"
	DefaultDocDir     = "/usr/local/share/doc/faramir"
	DefaultRunDir     = "/run/faramir"
	DefaultLogDir     = "/var/log/faramir"

	// Not derived from a layout field: logrotate reads one directory and the
	// path is the distribution's, not this install's, however the config and
	// the log are moved.
	logrotateConfig = "/etc/logrotate.d/faramir"

	DefaultGroup      = "dev"
	DefaultBrokerUser = "faramir-broker"
	DefaultKeeperUser = "faramir-keeper"
	DefaultExecUser   = "faramir-exec"

	// The group the store used to be owned by, when the broker was in it too.
	// Named only so an install can say that it is now unused; nothing is
	// created with it and nothing is looked up by it.
	legacyStoreGroup = "faramir-secrets"
)

// There is no DefaultStoreGroup.  The store group defaults to the keeper's own
// primary group, which the account already has, so the set of accounts that can
// read the ciphertext is the one account that decrypts it, by construction
// rather than by a membership list that has to be kept accurate.

// Layout is everything the templates and the install steps need to agree on.
// Built once by Options.layout and passed down, so no step can resolve a path
// differently from the one that wrote the unit naming it.
type Layout struct {
	// Group admits a caller to the broker socket and shares a working tree with
	// the executor.  The operator is in it, and so is anything running as the
	// operator, which is the point: asking the broker for a value by name is
	// what an agent is meant to do.
	//
	// StoreGroup is separate because reading the ciphertext is not that.  It
	// owns the secrets directory, and the only account in it is the keeper,
	// which is the only one that opens a managed file: it decrypts them, and it
	// fingerprints them for the broker's staleness check.  The operator is not
	// in it, so editing a store needs sudo.  One group for both would mean
	// every caller allowed to ask for a value by name could also read and
	// replace the file it comes from, and an agent that runs as the operator
	// would inherit exactly that.
	//
	// It defaults to KeeperUser, the keeper's own primary group.  Naming a
	// different one still works and is what --store-group is for; what it buys
	// is a second reader, which nothing here needs.
	Group      string
	StoreGroup string
	BrokerUser string
	KeeperUser string
	ExecUser   string

	ConfigDir  string
	ConfigFile string
	SecretsDir string
	BinDir     string
	LibexecDir string
	DocDir     string
	RunDir     string
	LogDir     string

	AgeKeyPath string
	// SSHKey is the identity the broker lends to brokered commands.  It renders
	// into config.toml's [ssh] keys, which is why it is here and not only on
	// Options: the config is written from this struct on every run, so the flag
	// and the file cannot drift apart.  Empty leaves the list empty, which is a
	// working setup with no agent.
	SSHKey string
}

// AgeKeyDir is where the key lives, which is the config directory: the key
// follows the config so that a store in an encrypted home has the key that
// opens it in there too.
func (l Layout) AgeKeyDir() string { return filepath.Dir(l.AgeKeyPath) }

// BrokerHome, KeeperHome and ExecHome are the service accounts' homes.  Derived
// from the account names so that renaming one does not leave it living in a
// directory named after the old one, which is also what StateDirectory= in each
// unit is rendered with.
func (l Layout) BrokerHome() string { return "/var/lib/" + l.BrokerUser }
func (l Layout) KeeperHome() string { return "/var/lib/" + l.KeeperUser }
func (l Layout) ExecHome() string   { return "/var/lib/" + l.ExecUser }

// KeeperBinds is what has to be bound back into the keeper's mount namespace,
// already formatted as BindReadOnlyPaths= values.
//
// The keeper is the uid that holds the age key, so it runs with the homes taken
// away entirely.  A config or a store kept in one is then not merely unreadable
// but absent, so ProtectHome drops to tmpfs and only those directories are bound
// back: every other home stays invisible.
//
// Empty when both sit outside the homes, which is the case ProtectHome=true
// covers and the one to prefer.
func (l Layout) KeeperBinds() []string {
	var inHomes []string
	for _, dir := range []string{l.ConfigDir, l.SecretsDir} {
		if homeOf(dir) != "" {
			inHomes = append(inHomes, dir)
		}
	}
	var out []string
	for _, dir := range minimal(inHomes) {
		// A leading "-" on the store only.  An encrypted home is not mounted
		// until its owner logs in, and a required bind on an absent path fails
		// the unit with a mount-namespace error; optional leaves the keeper up
		// to report which file it could not load.  The config is not optional:
		// a keeper without one exits before it opens a socket either way, and
		// the mount error at least names the path.
		if dir == l.SecretsDir && dir != l.ConfigDir {
			out = append(out, "-"+dir)
			continue
		}
		out = append(out, dir)
	}
	return out
}

// minimal drops any path contained in another, so a store inside the config
// directory produces one bind rather than two nested ones.
func minimal(paths []string) []string {
	var out []string
	for _, path := range paths {
		covered := false
		for _, other := range paths {
			if other != path && within(other, path) {
				covered = true
				break
			}
		}
		if !covered && !slices.Contains(out, path) {
			out = append(out, path)
		}
	}
	return out
}

// within reports whether path is at or under root.  Compared as path elements,
// so /home/operator2 is not inside /home/operator.
func within(root, path string) bool {
	rel, err := filepath.Rel(root, path)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
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
	for name, dir := range map[string]string{
		"config dir":  l.ConfigDir,
		"secrets dir": l.SecretsDir,
	} {
		if !filepath.IsAbs(dir) {
			return fmt.Errorf("%s must be an absolute path: %s", name, dir)
		}
		// systemd word-splits Environment= and expands % specifiers in it, so a
		// path holding either reaches the daemons truncated or not at all.
		if strings.ContainsAny(dir, " \t") {
			return fmt.Errorf("%s must not contain whitespace: %s", name, dir)
		}
		if strings.Contains(dir, "%") {
			return fmt.Errorf("%s must not contain '%%': %s", name, dir)
		}
		// Every unit sets PrivateTmp=true, which gives each its own /tmp and
		// /var/tmp, so nothing installed there is the file the daemons open.
		if within("/tmp", dir) || within("/var/tmp", dir) {
			return fmt.Errorf("%s cannot be under /tmp or /var/tmp: every unit sets "+
				"PrivateTmp=true, so nothing there is the file you installed", name)
		}
	}
	for name, account := range map[string]string{
		"group":       l.Group,
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
	// tighter install, it is one where the executor's uid holds the age key or
	// the audit log, which is the whole thing this project is for.
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
	return nil
}

// homeIsMounted reports whether an encrypted home has been unlocked.
//
// Writing into one before its owner logs in lands in the unencrypted backing
// store, where it is shadowed and invisible the moment the home mounts: the
// install looks like it worked and the daemons never see the file again.  A
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
