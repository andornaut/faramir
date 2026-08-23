package install

// Accounts and the shared group, which is what actually protects the secrets.
//
//	uid <operator>    runs the coding agent; member of the client group
//	uid keeper        holds the age key; execs nothing but sops
//	uid broker        holds the SSH keys and the audit log; policy and redaction
//	uid exec          forks brokered commands; holds nothing
//	group <client>    access to a tree brokered commands run in
//	group <secrets>   read on the ciphertext; the keeper's own group by default
//
// Three service uids because anything a uid can read, a command running as that
// uid can read. Two groups because being admitted to the broker socket and
// being able to read the file a value comes from are different privileges. The
// coding agent has no account: it runs as the operator, whose uid cannot read
// what the keeper and broker hold either. See docs/design.md.

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// serviceAccount is one of the three uids and where its state lives.
type serviceAccount struct {
	name string
	home string
	// sshDir is created for the accounts that keep keys: the broker's holds the
	// identity it lends, the executor's is where keys would live with [ssh] key
	// unset.
	sshDir bool
	// clientGroup joins Layout.ClientGroup, which for a service account is for the
	// tree rather than for the socket: the broker stats a request's cwd and the
	// executor runs there.
	clientGroup bool
}

func (r *runner) serviceAccounts() []serviceAccount {
	return []serviceAccount{
		// A real, writable home: it holds the SSH keys and ansible creates
		// ~/.ansible/tmp. In the client group because it stats a request's cwd,
		// which may sit inside a 0700 home.
		{name: r.layout.BrokerUser, home: r.layout.BrokerHome(), sshDir: true, clientGroup: true},
		// The keeper holds the age key and nothing else; a home only because sops
		// writes ~/.config. Out of the client group: it opens no path under a
		// home, and it is the one uid that can decrypt every managed file.
		{name: r.layout.KeeperUser, home: r.layout.KeeperHome()},
		// The uid every brokered command runs as; a home because ansible creates
		// ~/.ansible/tmp unconditionally.
		{name: r.layout.ExecUser, home: r.layout.ExecHome(), sshDir: true, clientGroup: true},
	}
}

func (r *runner) stepAccounts() error {
	changed := false
	// The shared group admits people, so it belongs in the login-account range
	// groupadd allocates in without -r. The secrets group is not created here:
	// it defaults to the keeper's primary group, which useradd creates below, and
	// shadow refuses to create an account whose group name is taken.
	if !groupExists(r.layout.ClientGroup) {
		if !r.opts.DryRun {
			if _, err := r.command("groupadd", r.layout.ClientGroup); err != nil {
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
	// A secrets group named with --secrets-group, or a keeper whose primary group
	// was not named after it. -r puts it in the system range below GID_MIN.
	if !groupExists(r.layout.SecretsGroup) {
		if !r.opts.DryRun {
			if _, err := r.command("groupadd", "-r", r.layout.SecretsGroup); err != nil {
				return err
			}
		}
		changed = true
	}
	// The one account that opens a managed file, decrypting and fingerprinting
	// them. A no-op when the secrets group is the keeper's own. The broker is
	// absent: it holds the plaintext already, so membership would add only
	// ciphertext it never decrypts.
	made, err := r.ensureInGroup(r.layout.KeeperUser, r.layout.SecretsGroup)
	if err != nil {
		return err
	}
	changed = changed || made

	r.step("accounts", changed, fmt.Sprintf("groups %s and %s, users %s",
		r.layout.ClientGroup, r.layout.SecretsGroup,
		strings.Join([]string{r.layout.BrokerUser, r.layout.KeeperUser, r.layout.ExecUser}, ", ")))

	// A secrets group allocated without -r sits in the login-account range, where
	// the next allocation collides with it. Reported rather than moved: groupmod
	// leaves every file owned by the old gid behind.
	if gid, err := lookupGroup(r.layout.SecretsGroup); err == nil {
		if first := firstLoginGID(); gid >= first {
			r.warnf("group %s has gid %d, in the range login.defs reserves for "+
				"login accounts; it holds only service accounts and belongs "+
				"below %d, where a host's own numbering will not reach it. "+
				"Move it with `groupdel %s && groupadd -r %s`, then re-run this "+
				"install: it re-owns the secrets directory to the new gid and restarts the "+
				"daemons onto it",
				r.layout.SecretsGroup, gid, first, r.layout.SecretsGroup, r.layout.SecretsGroup)
		}
	}

	if err := r.refuseOpenBoundaries(); err != nil {
		return err
	}

	joined, err := r.joinOperatorToGroup()
	if err != nil {
		return err
	}
	r.step("operator group", joined, fmt.Sprintf("%s in %s", r.opts.AgentUser, r.layout.ClientGroup))

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
	// A dry run reports the accounts it would create, so the membership one of
	// them would gain is part of that report rather than a lookup failure.
	if r.opts.DryRun && !userExists(account) {
		return true, nil
	}
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
			argv = append(argv, "-G", r.layout.ClientGroup)
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
			in, err := inGroup(account.name, r.layout.ClientGroup)
			if err != nil {
				return false, err
			}
			if !in {
				if !r.opts.DryRun {
					if _, err := r.command("usermod", "-aG", r.layout.ClientGroup, account.name); err != nil {
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
	// The account's primary group, not a group that happens to share its name:
	// an adopted account's need not be called after it, and the home and the
	// .ssh below are chowned to whatever this answers. resolveIDs reads the
	// same way, and this runs before it.
	if id, _, err := primaryGroup(account.name); err == nil {
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
	in, err := inGroup(r.opts.AgentUser, r.layout.ClientGroup)
	if err != nil || in {
		return false, err
	}
	if r.opts.DryRun {
		return true, nil
	}
	if _, err := r.command("usermod", "-aG", r.layout.ClientGroup, r.opts.AgentUser); err != nil {
		return false, err
	}
	// New group membership does not reach a session that is already open.
	r.warnf("%s must log out and back in for membership of %s to take effect",
		r.opts.AgentUser, r.layout.ClientGroup)
	return true, nil
}

// ensureOperatorUmask appends umask 002 to the operator's .bashrc, without
// which the operator and a brokered command fight over every new file in a
// shared tree. Here rather than in share-tree, belonging to the account.
func (r *runner) ensureOperatorUmask() (bool, error) {
	home, err := homeDir(r.opts.AgentUser)
	if err != nil {
		return false, err
	}
	profile := filepath.Join(home, ".bashrc")
	// One descriptor, opened before the contents are read and checked through
	// that same descriptor. A dotfile manager may symlink .bashrc, so the link
	// is followed and where it lands is checked: without the owner check,
	// pointing it at a file root can write turns this into an arbitrary append.
	//
	// Read-only under a dry run, which writes nothing and runs unprivileged.
	// Nothing below is fatal: this step runs before the directories, binaries,
	// config and units, so failing the run over a profile would leave the host
	// with no broker at all.
	skip := func(format string, args ...any) {
		r.warnf(format+". Add `umask 002` to your shell profile by hand if you share "+
			"a tree with brokered commands", args...)
	}
	// What it is, before opening it: this runs as root on a path in a directory
	// the account the agent runs as can write, and a device node there would be
	// armed by the open itself.
	switch resolved, err := os.Stat(profile); {
	case errors.Is(err, os.ErrNotExist):
		// The account may not use bash at all.
		return false, nil
	case err != nil:
		skip("could not read %s (%v)", profile, err)
		return false, nil
	case !resolved.Mode().IsRegular():
		skip("%s is not a regular file", profile)
		return false, nil
	}
	access := os.O_RDWR | os.O_APPEND
	if r.opts.DryRun {
		access = os.O_RDONLY
	}
	// O_NONBLOCK in case the check above lost a race with the path being
	// re-pointed: it keeps a fifo from waiting for a writer. The descriptor is
	// checked again below, which is what decides.
	handle, err := os.OpenFile(profile, access|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	if err != nil {
		skip("could not open %s (%v)", profile, err)
		return false, nil
	}
	defer func() { _ = handle.Close() }()
	info, err := handle.Stat()
	if err != nil {
		skip("could not read %s (%v)", profile, err)
		return false, nil
	}
	operatorUID, err := lookupUser(r.opts.AgentUser)
	if err != nil {
		skip("cannot resolve %s (%v)", r.opts.AgentUser, err)
		return false, nil
	}
	if !info.Mode().IsRegular() {
		skip("%s is not a regular file", profile)
		return false, nil
	}
	if wrong, err := wrongOwner(info, operatorUID, keep); err != nil {
		return false, err
	} else if wrong {
		skip("%s resolves to a file %s does not own, and appending to it as "+
			"root would write wherever it points", profile, r.opts.AgentUser)
		return false, nil
	}
	current, err := io.ReadAll(handle)
	if err != nil {
		skip("could not read %s (%v)", profile, err)
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
	_, err = handle.WriteString(
		"\n# shared dev tree: let group members edit each other's files\numask 002\n")
	return err == nil, err
}

// resolveIDs reads back the accounts created above, everything after this
// writing files owned by them. Under DryRun they may not exist, and ownership
// is then left alone.
func (r *runner) resolveIDs() error {
	r.operatorUID, r.brokerUID, r.keeperUID, r.execUID = keep, keep, keep, keep
	r.operatorGID, r.brokerGID, r.keeperGID, r.execGID = keep, keep, keep, keep
	r.secretsGID = keep
	lookups := []struct {
		name string
		into *int
		user bool
	}{
		{r.opts.AgentUser, &r.operatorUID, true},
		{r.layout.BrokerUser, &r.brokerUID, true},
		{r.layout.KeeperUser, &r.keeperUID, true},
		{r.layout.ExecUser, &r.execUID, true},
		{r.layout.SecretsGroup, &r.secretsGID, false},
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
	// Each service account's primary group, by gid and by name, rather than
	// assuming a group exists called what the account is: an adopted account's
	// need not. The name renders into [ssh] exec_group and the units' Group= and
	// SocketGroup=, and the gid is what the installed files are chowned to.
	for _, account := range []struct {
		user  string
		group *string
		gid   *int
	}{
		{r.layout.ExecUser, &r.layout.ExecGroup, &r.execGID},
		{r.layout.BrokerUser, &r.layout.BrokerGroup, &r.brokerGID},
		{r.layout.KeeperUser, &r.layout.KeeperGroup, &r.keeperGID},
	} {
		if gid, name, err := primaryGroup(account.user); err == nil {
			*account.group = name
			*account.gid = gid
		} else if !r.opts.DryRun {
			return err
		}
	}
	// The operator's own group, by the same reasoning: a directory created under
	// their home has to end up grouped to them rather than to the creating
	// process's group.
	if gid, _, err := primaryGroup(r.opts.AgentUser); err == nil {
		r.operatorGID = gid
	} else if !r.opts.DryRun {
		return err
	}
	home, err := homeDir(r.opts.AgentUser)
	if err != nil {
		return err
	}
	r.operatorHome = home
	return nil
}

// Where GID_MIN is configured. A variable so a test can point at one it wrote.
var loginDefs = "/etc/login.defs"

// refuseOpenBoundaries refuses an install whose account memberships defeat the
// split it is installing. Reported and not corrected: a membership this did not
// add is somebody else's decision, and removing an account from a group is not
// faramir's to do.
//
// Fatal rather than warned. `faramir doctor` reports these as failures, and an
// install that finished on a host where they hold would leave the two saying
// different things about the same boundary. Both are cleared by removing the
// membership and running this again.
//
// Every one that holds is named, not the first: they are cleared with one
// command each, and a run that named one at a time would cost a re-run apiece.
//
// One membership is named once, whichever reasons it breaks. The secrets group
// defaults to the keeper's own group, so on a default install one membership
// answers both checks below, and what an operator counts is commands to run
// rather than reasons a group is wrong.
func (r *runner) refuseOpenBoundaries() error {
	var open []string
	named := map[string]bool{}
	add := func(who, group, why string) {
		key := who + " " + group
		if named[key] {
			return
		}
		named[key] = true
		open = append(open, fmt.Sprintf("%s is in %s, %s (`gpasswd -d %s %s`)",
			who, group, why, who, group))
	}
	// The secrets group is what makes editing a secret need sudo.
	for _, who := range []string{r.layout.ExecUser, r.opts.AgentUser} {
		if who == "" {
			continue
		}
		if in, err := inGroup(who, r.layout.SecretsGroup); err == nil && in {
			add(who, r.layout.SecretsGroup, "so it can read and replace the managed "+
				"sops files directly, and the secrets directory is only as protected "+
				"as whatever runs as that account")
		}
	}
	// A command that could read the broker's or the keeper's group holds the
	// audit log or the age key.
	for _, forbidden := range []string{r.layout.BrokerUser, r.layout.KeeperUser} {
		if in, err := inGroup(r.layout.ExecUser, forbidden); err == nil && in {
			add(r.layout.ExecUser, forbidden, "which is the boundary between a "+
				"brokered command and the age key or the audit log")
		}
	}
	if len(open) == 0 {
		return nil
	}
	return fmt.Errorf("this host's group memberships defeat the split this "+
		"install draws, and clearing them is not faramir's to do:\n  %s",
		strings.Join(open, "\n  "))
}

// firstLoginGID is GID_MIN, the bottom of the login-account range and so one
// past the top of the system range `groupadd -r` allocates in. Debian and
// Ubuntu ship GID_MIN set and SYS_GID_MIN commented out; anything unreadable
// falls back to their value.
func firstLoginGID() int {
	const fallback = 1000
	data, err := os.ReadFile(loginDefs)
	if err != nil {
		return fallback
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		// A commented-out setting keeps its name prefixed, so it never matches.
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
		return false, nil //nolint:nilerr // an absent group is an answer, not a failure
	}
	ids, err := entry.GroupIds()
	if err != nil {
		return false, err
	}
	return slices.Contains(ids, target.Gid), nil
}
