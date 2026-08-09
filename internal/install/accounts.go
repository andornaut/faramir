package install

// Accounts and the shared group, which is what actually protects the secrets.
//
//	uid <operator>    runs the coding agent; member of the shared group
//	uid keeper        holds the age key; execs nothing but sops
//	uid broker        holds the SSH keys and the audit log; policy and redaction
//	uid exec          forks brokered commands; holds nothing
//	group <shared>    access to a tree brokered commands run in
//	group <store>     read on the ciphertext; the keeper's own group by default
//
// Three uids because anything a uid can read, a command running as that uid can
// read.  Two groups because being admitted to the broker socket and being able
// to read the file a value comes from are different privileges; the store group
// holds the keeper alone, so it needs no membership list.
//
// The coding agent has no account: it runs as the operator, whose uid cannot
// read what the keeper and broker hold either.  See docs/design.md.

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
)

// serviceAccount is one of the three uids and where its state lives.
type serviceAccount struct {
	name string
	home string
	// sshDir is created for the accounts that keep keys: the broker's holds the
	// identity it lends, the executor's is where keys would live with [ssh]
	// keys empty.
	sshDir bool
	// clientGroup grants traversal into the operator's home, for the two uids
	// that must reach a working tree.
	clientGroup bool
}

func (r *runner) serviceAccounts() []serviceAccount {
	return []serviceAccount{
		// A real, writable home: it holds the SSH keys and ansible creates
		// ~/.ansible/tmp.  Under /var/lib, which the unit grants itself with
		// StateDirectory=.  In the client group because it stats a request's
		// cwd, which may sit inside a 0700 home.
		{name: r.layout.BrokerUser, home: r.layout.BrokerHome(), sshDir: true, clientGroup: true},
		// The keeper holds the age key and nothing else; a home only because
		// sops writes ~/.config.  Out of the client group: it opens no path
		// under a home, and it is the one uid that can decrypt every managed
		// file.
		{name: r.layout.KeeperUser, home: r.layout.KeeperHome()},
		// The uid every brokered command runs as; a home because ansible
		// creates ~/.ansible/tmp unconditionally.
		{name: r.layout.ExecUser, home: r.layout.ExecHome(), sshDir: true, clientGroup: true},
	}
}

func (r *runner) stepAccounts() error {
	changed := false
	// The shared group admits people, so it belongs in the login-account range
	// groupadd allocates in without -r.
	//
	// The store group is not created here: it defaults to the keeper's primary
	// group, which useradd creates below, and shadow refuses to create an
	// account whose group name is taken.
	if !groupExists(r.layout.Group) {
		if !r.opts.DryRun {
			if _, err := r.command("groupadd", r.layout.Group); err != nil {
				return err
			}
		}
		changed = true
	}
	for _, account := range r.serviceAccounts() {
		made, err := r.ensureServiceAccount(account)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	// A store group named with --store-group, or a keeper whose primary group
	// was not named after it.  -r puts it in the system range below GID_MIN;
	// without it shadow allocates in the login-account range.
	if !groupExists(r.layout.StoreGroup) {
		if !r.opts.DryRun {
			if _, err := r.command("groupadd", "-r", r.layout.StoreGroup); err != nil {
				return err
			}
		}
		changed = true
	}
	// The one account that opens a managed file, decrypting and fingerprinting
	// them.  A no-op when the store group is the keeper's own.
	//
	// The broker is absent: it holds the plaintext already, so membership would
	// only add ciphertext it never decrypts, including files no [secrets] list
	// names.
	made, err := r.ensureInGroup(r.layout.KeeperUser, r.layout.StoreGroup)
	if err != nil {
		return err
	}
	changed = changed || made

	r.step("accounts", changed, fmt.Sprintf("groups %s and %s, users %s",
		r.layout.Group, r.layout.StoreGroup,
		strings.Join([]string{r.layout.BrokerUser, r.layout.KeeperUser, r.layout.ExecUser}, ", ")))

	// A store group allocated without -r sits in the login-account range, where
	// the next allocation collides with it.  Reported rather than moved:
	// groupmod leaves every file owned by the old gid behind, and the operator
	// may have put it there deliberately.
	if gid, err := lookupGroup(r.layout.StoreGroup); err == nil {
		if first := firstLoginGID(); gid >= first {
			r.warn("group %s has gid %d, in the range login.defs reserves for "+
				"login accounts; it holds only service accounts and belongs "+
				"below %d, where a host's own numbering will not reach it. "+
				"Move it with `groupdel %s && groupadd -r %s`, then re-run this "+
				"install: it re-owns the store to the new gid and restarts the "+
				"daemons onto it",
				r.layout.StoreGroup, gid, first, r.layout.StoreGroup, r.layout.StoreGroup)
		}
	}

	// The store group is what makes editing a secret need sudo.  Reported
	// rather than removed, a membership this did not add being somebody else's
	// decision.
	for _, who := range []string{r.layout.ExecUser, r.opts.Operator} {
		if who == "" {
			continue
		}
		in, err := inGroup(who, r.layout.StoreGroup)
		if err != nil || !in {
			continue
		}
		r.warn("%s is in group %s, so it can read and replace the managed sops "+
			"files directly; remove it, or the store is only as protected as "+
			"whatever runs as that account", who, r.layout.StoreGroup)
	}

	// A command that could read the broker's or the keeper's group holds the
	// audit log or the age key.  Warned rather than fixed.
	for _, forbidden := range []string{r.layout.BrokerUser, r.layout.KeeperUser} {
		in, err := inGroup(r.layout.ExecUser, forbidden)
		if err != nil {
			continue
		}
		if in {
			r.warn("%s is in group %s; remove it, that is the boundary between "+
				"a brokered command and the age key or the audit log",
				r.layout.ExecUser, forbidden)
		}
	}

	joined, err := r.joinOperatorToGroup()
	if err != nil {
		return err
	}
	r.step("operator group", joined, fmt.Sprintf("%s in %s", r.opts.Operator, r.layout.Group))

	umask, err := r.ensureOperatorUmask()
	if err != nil {
		return err
	}
	r.step("operator umask", umask, "umask 002 for the shared tree")
	return nil
}

// ensureInGroup adds an existing account to a supplementary group, and reports
// whether it had to.
func (r *runner) ensureInGroup(account, group string) (bool, error) {
	in, err := inGroup(account, group)
	if err != nil || in {
		return false, err
	}
	if !r.opts.DryRun {
		if _, err := r.command("usermod", "-aG", group, account); err != nil {
			return false, err
		}
	}
	return true, nil
}

func (r *runner) ensureServiceAccount(account serviceAccount) (bool, error) {
	changed := false
	switch {
	case !userExists(account.name):
		argv := []string{"useradd", "-r", "-m", "-d", account.home}
		if account.clientGroup {
			argv = append(argv, "-G", r.layout.Group)
		}
		argv = append(argv, "-s", "/usr/sbin/nologin", account.name)
		if !r.opts.DryRun {
			if _, err := r.command(argv[0], argv[1:]...); err != nil {
				return false, err
			}
		}
		changed = true
	default:
		if account.clientGroup {
			in, err := inGroup(account.name, r.layout.Group)
			if err != nil {
				return false, err
			}
			if !in {
				if !r.opts.DryRun {
					if _, err := r.command("usermod", "-aG", r.layout.Group, account.name); err != nil {
						return false, err
					}
				}
				changed = true
			}
		}
		// An account whose home moved keeps writing to the old path, which then
		// holds the SSH keys while StateDirectory= names the new one.
		if current, err := homeDir(account.name); err == nil && current != account.home {
			if !r.opts.DryRun {
				if _, err := r.command("usermod", "-d", account.home, account.name); err != nil {
					return false, err
				}
			}
			changed = true
		}
	}
	if r.opts.DryRun && !userExists(account.name) {
		return changed, nil
	}
	uid, gid := keep, keep
	if id, err := lookupUser(account.name); err == nil {
		uid = id
	}
	if id, err := lookupGroup(account.name); err == nil {
		gid = id
	}
	// Created but not re-asserted: each home is a StateDirectory=, and systemd
	// applies StateDirectoryMode on every start.
	made, err := r.fs.ensureDir(account.home, 0o700, uid, gid, false)
	if err != nil {
		return false, err
	}
	changed = changed || made
	if !account.sshDir {
		return changed, nil
	}
	made, err = r.fs.ensureDir(filepath.Join(account.home, ".ssh"), 0o700, uid, gid, true)
	return changed || made, err
}

func (r *runner) joinOperatorToGroup() (bool, error) {
	in, err := inGroup(r.opts.Operator, r.layout.Group)
	if err != nil || in {
		return false, err
	}
	if r.opts.DryRun {
		return true, nil
	}
	if _, err := r.command("usermod", "-aG", r.layout.Group, r.opts.Operator); err != nil {
		return false, err
	}
	// New group membership does not reach a session that is already open.
	r.warn("%s must log out and back in for membership of %s to take effect",
		r.opts.Operator, r.layout.Group)
	return true, nil
}

// ensureOperatorUmask appends umask 002 to the operator's .bashrc, without
// which the operator and a brokered command fight over every new file in a
// shared tree.  Here rather than in share-tree, belonging to the account.
func (r *runner) ensureOperatorUmask() (bool, error) {
	home, err := homeDir(r.opts.Operator)
	if err != nil {
		return false, err
	}
	profile := filepath.Join(home, ".bashrc")
	current, err := os.ReadFile(profile)
	if err != nil {
		// The account may not use bash at all.
		return false, nil
	}
	for line := range strings.Lines(string(current)) {
		if strings.HasPrefix(strings.TrimSpace(line), "umask 002") {
			return false, nil
		}
	}
	if r.opts.DryRun {
		return true, nil
	}
	// Mode 0: never applied without O_CREATE, and this only appends.
	handle, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = handle.Close() }()
	_, err = handle.WriteString(
		"\n# shared dev tree: let group members edit each other's files\numask 002\n")
	return err == nil, err
}

// resolveIDs reads back the accounts created above, everything after this
// writing files owned by them.  Under DryRun they may not exist, and ownership
// is then left alone.
func (r *runner) resolveIDs() error {
	r.operatorUID, r.brokerUID, r.keeperUID, r.execUID = keep, keep, keep, keep
	r.groupGID, r.brokerGID, r.keeperGID, r.execGID = keep, keep, keep, keep
	r.storeGID = keep
	lookups := []struct {
		name string
		into *int
		user bool
	}{
		{r.opts.Operator, &r.operatorUID, true},
		{r.layout.BrokerUser, &r.brokerUID, true},
		{r.layout.KeeperUser, &r.keeperUID, true},
		{r.layout.ExecUser, &r.execUID, true},
		{r.layout.Group, &r.groupGID, false},
		{r.layout.StoreGroup, &r.storeGID, false},
		{r.layout.BrokerUser, &r.brokerGID, false},
		{r.layout.KeeperUser, &r.keeperGID, false},
		{r.layout.ExecUser, &r.execGID, false},
	}
	for _, lookup := range lookups {
		var id int
		var err error
		if lookup.user {
			id, err = lookupUser(lookup.name)
		} else {
			id, err = lookupGroup(lookup.name)
		}
		if err != nil {
			if r.opts.DryRun {
				continue
			}
			return err
		}
		*lookup.into = id
	}
	home, err := homeDir(r.opts.Operator)
	if err != nil {
		return err
	}
	r.operatorHome = home
	return nil
}

// Where GID_MIN is configured.  A variable so a test can point at one it wrote.
var loginDefs = "/etc/login.defs"

// firstLoginGID is GID_MIN, the bottom of the login-account range and so one
// past the top of the system range `groupadd -r` allocates in.  Debian and
// Ubuntu ship GID_MIN set and SYS_GID_MIN commented out, so this reads the one
// that is there; anything unreadable falls back to their value.
func firstLoginGID() int {
	const fallback = 1000
	data, err := os.ReadFile(loginDefs)
	if err != nil {
		return fallback
	}
	for _, line := range strings.Split(string(data), "\n") {
		// A commented-out setting keeps its name prefixed, so it never
		// matches.
		fields := strings.Fields(line)
		if len(fields) != 2 || fields[0] != "GID_MIN" {
			continue
		}
		gid, err := strconv.Atoi(fields[1])
		if err != nil {
			return fallback
		}
		return gid
	}
	return fallback
}

func homeDir(name string) (string, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("no such user %q: %w", name, err)
	}
	return entry.HomeDir, nil
}

// inGroup reports membership, primary or supplementary.
func inGroup(name, group string) (bool, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return false, err
	}
	// A group that does not exist is one nobody is in, which is the dry-run
	// case.
	target, err := user.LookupGroup(group)
	if err != nil {
		return false, nil
	}
	ids, err := entry.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, target.Gid), nil
}
