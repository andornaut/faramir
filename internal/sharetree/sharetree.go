// Package sharetree makes one directory usable by brokered commands.
//
//	shared     group-owned and setgid, so the operator and a brokered command
//	           do not fight over every file either creates (with umask 002)
//	reachable  a home is 0700, so every directory above the tree has to be
//	           group-executable by a group the executor is in
//
// Nothing in faramir needs a tree of its own; this is for the operator who
// wants to run commands somewhere their own uid owns.
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
// granted traversal.
type Options struct {
	Dir      string
	Operator string
	Group    string
	// Log receives one line per step, already formatted.
	Log func(string)
}

// Resolve is the absolute, symlink-free path of a directory to share.  Chmod
// and Chown follow a symlink while WalkDir does not, so a symlinked argument
// rewrites the mode and group of whatever it points at, shares none of the
// files under it, and reports success.  Refusals compare against this too, a
// check on the argument answering a question about the link.
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
	// MkdirAll applies the umask and an existing directory keeps its mode, so
	// setgid is set explicitly.
	if err := os.Chmod(dir, 0o2770|os.ModeSetgid); err != nil {
		return err
	}
	if err := shareTree(dir, gid); err != nil {
		return err
	}
	opts.logf("shared %s with %s", dir, opts.Group)

	// Only inside the operator's home; outside, the modes already allow it.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return nil
	}
	return grantTraversal(home, dir, opts, gid)
}

// Reachable is Share's second job alone: every directory from the operator's
// home down to dir is made enterable by the group, and dir is left as it was.
//
// For the directories the daemons only read.  Share is wrong for those: a
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
	// Outside the homes the modes already allow it.
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

// resolvedHome is the account's home with symlinks taken out, to compare
// against a tree resolved the same way: otherwise a tree inside a symlinked
// home reads as outside every home.  Empty when passwd names no home, or one
// that is not there.
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

// within compares path elements, so /home/andornaut2 is not inside
// /home/andornaut.
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
		// Chowning a symlink would follow it out of the tree.
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}
		if err := os.Lchown(path, -1, gid); err != nil {
			return err
		}
		return os.Chmod(path, groupShared(info.Mode()))
	})
}

// groupShared is "chmod g+rwX", plus setgid on a directory.  The X is why this
// is not a constant: a directory needs group execute to be entered, a file only
// when it was already executable for somebody.
//
// setgid is what makes it hold: a file either party creates inherits the group
// rather than the creator's own.
func groupShared(mode os.FileMode) os.FileMode {
	out := mode | 0o060
	switch {
	case mode.IsDir():
		out |= 0o010 | os.ModeSetgid
	case mode.Perm()&0o111 != 0:
		out |= 0o010
	}
	return out
}

// components lists every directory from home down to dir's parent, the tree
// itself being group-owned above.
func components(home, dir string) []string {
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
// by the shared group.  The group slot is the one going spare, the operator
// owning the home, and ownership is ordinary inode metadata that survives an
// encrypted home.
//
// Execute only, never read, so these uids pass through without listing.  Not
// "chmod o+x", which grants the same to every account on the machine.
func grantTraversal(home, dir string, opts Options, gid int) error {
	for _, component := range components(home, dir) {
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
			// The previous group loses whatever the group bits gave it.
			opts.logf("%s: group %s -> %s", component, groupName(info), opts.Group)
			if err := os.Chown(component, -1, gid); err != nil {
				return err
			}
		}
		if err := os.Chmod(component, traversalMode(info.Mode(), action == regroup)); err != nil {
			return err
		}
		opts.logf("%s: %s may now traverse it", component, opts.Group)
	}
	return nil
}

// traversalMode is what one directory on the path is chmodded to.  Group
// execute added, and on a regroup the group's read and write dropped first:
// those bits belonged to the previous group, and carrying them over to a group
// the executor is in would hand it read on a 0750 home, or write on a 0770 one.
// The owner's own bits are never touched.
func traversalMode(mode os.FileMode, regrouped bool) os.FileMode {
	if regrouped {
		mode &^= 0o070
	}
	return mode | 0o010
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
	// Already open to everyone.  Tightening a directory the operator left open
	// is not this command's business.
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
