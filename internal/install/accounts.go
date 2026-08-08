package install

// Accounts and the shared group.  This is the part that actually protects the
// secrets; everything else is ergonomics and blast-radius reduction on top of
// uid separation.
//
//	uid <operator>    runs the coding agent; member of the shared group
//	uid keeper        holds the age key; execs nothing but sops
//	uid broker        holds the SSH keys and the audit log; policy and redaction
//	uid exec          forks brokered commands; holds nothing
//	group <shared>    access to a tree brokered commands run in
//
// Three uids rather than one because anything a uid can read, a command running
// as that uid can read.  The keeper's key and the broker's audit log and SSH
// keys each sit behind a boundary the child cannot cross.
//
// There is no account for the coding agent.  It runs as the operator, because
// the work it is asked to do is the operator's: their checkouts, their gh
// credential, their commits.  What that gives up is a kernel boundary around the
// agent process, and what replaces it is not a weaker version of the same thing:
// the secrets this project exists to protect are behind the keeper and the
// broker, which the operator's uid cannot read either.  See docs/scope.md.

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"
)

// serviceAccount is one of the three uids and where its state lives.
type serviceAccount struct {
	name string
	home string
	// sshDir is created for the accounts that keep keys.  The broker's holds
	// the identity it lends; the executor's is where keys would have to live if
	// [ssh] keys were left empty, which is the arrangement to avoid.
	sshDir bool
}

func (r *runner) serviceAccounts() []serviceAccount {
	return []serviceAccount{
		// A real, writable home: it holds the SSH keys used to reach managed
		// hosts, and Ansible insists on creating ~/.ansible/tmp.  Under
		// /var/lib rather than /home because that is where a service account's
		// state belongs, and because the unit grants itself that path with
		// StateDirectory=.
		{name: r.layout.BrokerUser, home: r.layout.BrokerHome(), sshDir: true},
		// The keeper holds the age key and nothing else.  A home only because
		// sops writes ~/.config.  It must not share a uid with anything that
		// executes a command.
		{name: r.layout.KeeperUser, home: r.layout.KeeperHome()},
		// The uid every brokered command runs as.  A home because Ansible
		// creates ~/.ansible/tmp unconditionally.
		{name: r.layout.ExecUser, home: r.layout.ExecHome(), sshDir: true},
	}
}

func (r *runner) stepAccounts() error {
	changed := false
	for _, group := range []string{r.layout.Group, r.layout.StoreGroup} {
		if groupExists(group) {
			continue
		}
		if !r.opts.DryRun {
			if _, err := r.command("groupadd", group); err != nil {
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
	// Only the two that touch the ciphertext: the keeper decrypts the managed
	// files and the broker stats them to notice an edit.  The executor is left
	// out on purpose, because a brokered command runs as it, and the operator
	// is left out because an agent runs as the operator.
	for _, account := range []string{r.layout.BrokerUser, r.layout.KeeperUser} {
		made, err := r.ensureInGroup(account, r.layout.StoreGroup)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	r.step("accounts", changed, fmt.Sprintf("groups %s and %s, users %s",
		r.layout.Group, r.layout.StoreGroup,
		strings.Join([]string{r.layout.BrokerUser, r.layout.KeeperUser, r.layout.ExecUser}, ", ")))

	// The store group is what makes editing a secret need sudo.  A membership
	// this did not add is somebody else's decision, so it is reported rather
	// than removed, but it is worth saying loudly: either of these puts the
	// ciphertext back within reach of a uid that can already ask the broker for
	// the plaintext by name.
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

	// The executor must not be in the broker's or the keeper's group.  That is
	// the boundary: a command that could read either holds the audit log or the
	// age key.  Warned rather than fixed, because removing a membership this
	// did not add is somebody else's decision.
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
		if !r.opts.DryRun {
			if _, err := r.command("useradd", "-r", "-m", "-d", account.home,
				"-G", r.layout.Group, "-s", "/usr/sbin/nologin", account.name); err != nil {
				return false, err
			}
		}
		changed = true
	default:
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
		// An account whose home moved keeps working but writes to the old path,
		// which is then the one holding the SSH keys while the unit's
		// StateDirectory= names the new one.
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
	// Created but not re-asserted.  Each of these homes is a StateDirectory= on
	// the account's unit, and systemd applies StateDirectoryMode to it on every
	// start, so a mode asserted here is one the next start undoes and every run
	// afterwards reports as a change it never manages to make.
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

// ensureOperatorUmask appends umask 002 to the operator's .bashrc.
//
// Without it the operator and a brokered command fight over every new file in a
// shared tree.  It belongs to the account rather than to any one directory,
// which is why it is here and not in share-tree.
func (r *runner) ensureOperatorUmask() (bool, error) {
	home, err := homeDir(r.opts.Operator)
	if err != nil {
		return false, err
	}
	profile := filepath.Join(home, ".bashrc")
	current, err := os.ReadFile(profile)
	if err != nil {
		// No .bashrc is not this command's business to create: the account may
		// not use bash at all.
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
	// Mode 0: without O_CREATE it is never applied, and this only ever appends
	// to a file the account already has.
	handle, err := os.OpenFile(profile, os.O_APPEND|os.O_WRONLY, 0)
	if err != nil {
		return false, err
	}
	defer func() { _ = handle.Close() }()
	_, err = handle.WriteString(
		"\n# shared dev tree: let group members edit each other's files\numask 002\n")
	return err == nil, err
}

// resolveIDs reads back the accounts the step above created.  Separate because
// everything after it writes files owned by them, and under DryRun they may not
// exist, in which case ownership is left alone rather than guessed.
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

func homeDir(name string) (string, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return "", fmt.Errorf("no such user %q: %w", name, err)
	}
	return entry.HomeDir, nil
}

// inGroup reports whether an account is a member of a group, primary or
// supplementary, which is how the shared group is granted (usermod -aG).
func inGroup(name, group string) (bool, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return false, err
	}
	// A group that does not exist yet is one nobody is in.  An error here would
	// otherwise stop a dry run, which reports on a host before the group has
	// been created.
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
