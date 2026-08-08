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

// Share applies both jobs to one directory.
func Share(opts Options) error {
	dir, err := filepath.Abs(opts.Dir)
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
	if owner.HomeDir == "" || !within(owner.HomeDir, dir) {
		return nil
	}
	return grantTraversal(owner.HomeDir, dir, opts, gid)
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, args...))
	}
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
