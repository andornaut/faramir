// Package sharetree makes one directory usable by brokered commands.
//
// Two jobs, and only the second is conditional:
//
//	shared     the operator and a brokered command both write there, so the
//	           tree is group-owned and setgid, which with umask 002 keeps them
//	           from fighting over every file either one creates
//	reachable  a home is 0700, so the executor cannot enter a tree inside one
//	           until every directory above it is group-executable by a group the
//	           executor is in
//
// Nothing in faramir needs a tree of its own: the managed sops files are under
// /etc and a brokered command runs where its caller was.  This exists for the
// operator who wants to run commands somewhere their own uid owns.
package sharetree

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Options is one run.  Group is both what the tree is shared with and what is
// granted traversal, so the accounts that need to reach a tree are the members
// of that one group.
type Options struct {
	Dir      string
	Operator string
	Group    string
	// Log receives one line per step, already formatted.
	Log func(string)
}

// Resolve is the absolute, symlink-free path of a directory to share.
//
// Resolving is not tidiness here, it is the difference between sharing a tree
// and sharing something else.  Chmod and Chown follow a symlink and land on the
// target, while WalkDir does not: it lstats its root, finds a link, and
// descends into nothing.  A symlinked argument therefore rewrites the mode and
// group of whatever it points at, shares none of the files under it, and
// reports success.  Pointed at a home, that is the home group-writable with no
// walk to notice; pointed at a checkout, it is an enrolment that looks done and
// leaves every file in the tree unreachable to the executor.
//
// It is also what any refusal has to be applied to.  A check against the
// argument answers a question about the link rather than about the directory.
func Resolve(dir string) (string, error) {
	absolute, err := filepath.Abs(dir)
	if err != nil {
		return "", err
	}
	resolved, err := filepath.EvalSymlinks(absolute)
	if err != nil {
		return "", err
	}
	return resolved, nil
}

// Share applies both jobs to one directory.
func Share(opts Options) error {
	dir, err := Resolve(opts.Dir)
	if err != nil {
		return err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	uid, _ := strconv.Atoi(owner.Uid)
	gid, _ := strconv.Atoi(group.Gid)

	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return err
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return err
	}
	// MkdirAll applies the umask, and an existing directory keeps whatever mode
	// it had, so the setgid bit is set explicitly either way.
	if err := os.Chmod(dir, 0o2770|os.ModeSetgid); err != nil {
		return err
	}
	if err := shareTree(dir, gid); err != nil {
		return err
	}
	opts.logf("shared %s with %s", dir, opts.Group)

	// Only for a tree inside the operator's home.  Outside the homes the modes
	// already allow it and there is nothing to grant.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return nil
	}
	return grantTraversal(home, dir, opts, gid)
}

// Reachable is Share's second job on its own: every directory from the
// operator's home down to dir is made enterable by the group, and dir itself is
// left exactly as it was.
//
// For the directories the daemons only read.  A config kept in a home is
// unreachable to three service uids that a 0700 home excludes, and the symptom
// is not a permission message but a daemon that exits before it opens a socket.
// Share is wrong for those: it would make the config group-writable, and a
// config a brokered command can rewrite is the policy rewriting itself.
func Reachable(opts Options) error {
	dir, err := Resolve(opts.Dir)
	if err != nil {
		return err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	gid, _ := strconv.Atoi(group.Gid)
	// Outside the homes the modes already allow it and there is nothing to grant.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return nil
	}
	return grantTraversal(home, dir, opts, gid)
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, args...))
	}
}

// resolvedHome is the account's home with symlinks taken out, so that it can be
// compared against a tree that has had the same done to it.  Resolving one and
// not the other is how a tree inside a symlinked home reads as being outside
// every home, and then never gets the traversal it needs.
//
// Empty when passwd names no home, or names one that is not there: an account
// whose home cannot be resolved has no path to grant traversal along.
func resolvedHome(owner *user.User) string {
	if owner.HomeDir == "" {
		return ""
	}
	home, err := Resolve(owner.HomeDir)
	if err != nil {
		return ""
	}
	return home
}

// within reports whether dir is under home.  Compared as path elements, so
// /home/andornaut2 is not inside /home/andornaut.
func within(home, dir string) bool {
	rel, err := filepath.Rel(home, dir)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

func shareTree(root string, gid int) error {
	return filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		// Symlinks carry no useful mode and chowning one would follow it out of
		// the tree.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
		return os.Chmod(path, GroupShared(info.Mode()))
	})
}

// GroupShared is "chmod g+rwX", plus setgid on a directory.
//
// The X is the whole reason this is not a constant: group execute is added to a
// directory, which needs it to be entered, and to a file only when the file was
// already executable for somebody.  Granting it unconditionally would mark every
// ordinary file in the tree executable.
//
// setgid on the directories is what makes the arrangement hold: a file either
// the operator or a brokered command creates inherits the group rather than the
// creator's own, so the other one can still write it.
func GroupShared(mode os.FileMode) os.FileMode {
	out := mode | 0o060
	switch {
	case mode.IsDir():
		out |= 0o010 | os.ModeSetgid
	case mode.Perm()&0o111 != 0:
		out |= 0o010
	}
	return out
}

// Components lists every directory from home down to dir's parent, which are
// the ones needing traversal.  The tree itself is group-owned above, so it is
// not included.
func Components(home, dir string) []string {
	rel, err := filepath.Rel(home, dir)
	if err != nil || rel == "." {
		return nil
	}
	parts := strings.Split(rel, string(filepath.Separator))
	out := []string{home}
	at := home
	for _, part := range parts[:len(parts)-1] {
		at = filepath.Join(at, part)
		out = append(out, at)
	}
	return out
}

// grantTraversal makes every directory from the home down to the tree enterable
// by the shared group.
//
// The mode's group slot is the one going spare: the operator owns the home and
// nothing else needs the group bits there.  Ownership is ordinary inode
// metadata, so this passes through an encrypted home unchanged and needs no
// tooling beyond what coreutils provides.
//
// Execute only, never read: these uids pass through the home without being able
// to list it.  Not "chmod o+x", which grants the same to every account on the
// machine, and with umask 002 in force the files below are 0664, so that opens
// the home rather than a path through it.
func grantTraversal(home, dir string, opts Options, gid int) error {
	for _, component := range Components(home, dir) {
		info, err := os.Stat(component)
		if err != nil {
			return err
		}
		action, err := traversalAction(info, gid, component)
		if err != nil {
			return err
		}
		if action == leaveAlone {
			continue
		}
		if action == regroup {
			// The previous group loses whatever the group bits gave it: they now
			// describe a different group.  Said out loud because nothing else
			// will mention it.
			opts.logf("%s: group %s -> %s", component, groupName(info), opts.Group)
			if err := os.Chown(component, -1, gid); err != nil {
				return err
			}
		}
		if err := os.Chmod(component, info.Mode()|0o010); err != nil {
			return err
		}
		opts.logf("%s: %s may now traverse it", component, opts.Group)
	}
	return nil
}

type traversal int

const (
	leaveAlone traversal = iota
	addExecute
	regroup
)

// traversalAction decides what one directory on the path needs.
func traversalAction(info os.FileInfo, gid int, path string) (traversal, error) {
	mode := info.Mode().Perm()
	// Already open to everyone: nothing to grant, and nothing worth taking away
	// here either.  Tightening a directory the operator chose to leave open is
	// not this command's business.
	if mode&0o001 != 0 {
		return leaveAlone, nil
	}
	owned, err := ownedByGroup(path, gid)
	if err != nil {
		return leaveAlone, err
	}
	if owned {
		if mode&0o010 != 0 {
			return leaveAlone, nil
		}
		return addExecute, nil
	}
	return regroup, nil
}

func ownedByGroup(path string, gid int) (bool, error) {
	var st syscall.Stat_t
	if err := syscall.Stat(path, &st); err != nil {
		return false, err
	}
	return int(st.Gid) == gid, nil
}

func groupName(info os.FileInfo) string {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	if g, err := user.LookupGroupId(strconv.FormatUint(uint64(st.Gid), 10)); err == nil {
		return g.Name
	}
	return strconv.FormatUint(uint64(st.Gid), 10)
}
