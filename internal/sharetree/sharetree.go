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
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

// Options is one run. Group is both what the tree is shared with and what is
// granted traversal.
type Options struct {
	Dir      string
	Operator string
	Group    string
	// Keep names paths, relative to Dir, whose mode is not to be widened: the
	// files an enrolment writes into the tree. They are still regrouped, so the
	// group can read them at the mode their writer chose; what they must not
	// become is group-writable.
	//
	// That stops a write through the file and not a replacement of it, unlink and
	// rename being permissions on the directory. The directory each sits in is
	// made sticky for that reason; see stickyDirs, and what it leaves open at the
	// tree's root.
	//
	// This narrows what a shared tree grants rather than bounding it: the
	// invariant the install rests on is that no instruction the agent is given
	// can move a secret. `faramir doctor` reports a tree whose agent files
	// stopped carrying what the enrolment wrote.
	Keep []string
	// Log receives one line per step, already formatted.
	Log func(string)
}

// Resolve is the absolute, symlink-free path of a directory to share. Chmod
// and Chown follow a symlink while WalkDir does not, so a symlinked argument
// would rewrite the mode and group of whatever it points at, share none of the
// files under it, and report success. Refusals compare against this too.
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

// Result is what a run altered, counted rather than listed: a tree is thousands
// of entries, and what a caller reports is whether this run was the one that
// changed it.
type Result struct {
	// Changed is how many paths this run regrouped or rechmodded, entries in the
	// tree and directories above it granted traversal alike.
	Changed int
}

// Share applies both jobs to one directory.
func Share(opts Options) (Result, error) {
	var result Result
	dir, err := Resolve(opts.Dir)
	if err != nil {
		return result, err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return result, fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return result, fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	uid, _ := strconv.Atoi(owner.Uid)
	gid, _ := strconv.Atoi(group.Gid)

	if err := os.MkdirAll(dir, 0o2770); err != nil {
		return result, err
	}
	keep := make(map[string]bool, len(opts.Keep))
	for _, rel := range opts.Keep {
		keep[filepath.Clean(rel)] = true
	}
	sticky := stickyDirs(opts.Keep)
	// Asked before each operation, and the operation still made unconditionally:
	// what is counted is whether this run altered the host.
	const rootMode = 0o2770 | os.ModeSetgid
	if info, err := os.Stat(dir); err == nil {
		// One per path, not one per operation: a path needing both a regroup and a
		// widen is still one path.
		if wouldRegroup(info, gid) || wouldReown(info, uid) ||
			chmodBits(info.Mode()) != chmodBits(rootMode) {
			result.Changed++
		}
	}
	if err := os.Chown(dir, uid, gid); err != nil {
		return result, err
	}
	// MkdirAll applies the umask and an existing directory keeps its mode, so
	// setgid is set explicitly.
	if err := os.Chmod(dir, rootMode); err != nil {
		return result, err
	}
	changed, err := shareTree(dir, gid, keep, sticky)
	result.Changed += changed
	if err != nil {
		return result, err
	}
	opts.logf("shared %s with %s", dir, opts.Group)

	// Only inside the agent account's home; outside, the modes already allow
	// it.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return result, nil
	}
	changed, err = grantTraversal(home, dir, opts, gid)
	result.Changed += changed
	return result, err
}

// Reachable is Share's second job alone: every directory from the operator's
// home down to the path named is made enterable by the group, and that path
// itself is left as it was. For the directories the daemons only read, Share
// being wrong for those: a config a brokered command can rewrite is the policy
// rewriting itself.
//
// The last component is left alone whatever it is, because whatever names it
// grants it: Share sets the tree it is about to share, and a link grants the
// file it is about to read. So a caller wanting the directories that hold a
// file names the file, and one naming the directory gets everything above it
// and not the directory itself.
func Reachable(opts Options) (Result, error) {
	var result Result
	dir, err := Resolve(opts.Dir)
	if err != nil {
		return result, err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return result, fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return result, fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	gid, _ := strconv.Atoi(group.Gid)
	// Outside the homes the modes already allow it.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return result, nil
	}
	result.Changed, err = grantTraversal(home, dir, opts, gid)
	return result, err
}

func (o Options) logf(format string, args ...any) {
	if o.Log != nil {
		o.Log(fmt.Sprintf(format, args...))
	}
}

// resolvedHome is the account's home with symlinks taken out, to compare
// against a tree resolved the same way. Empty when passwd names no home, or
// one that is not there.
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

// shareTree regroups and widens every entry under root.
//
// Each operation goes through an os.Root rather than through the walked path:
// this runs as root over a tree the agent's uid can write, so between the walk
// seeing an entry and the mode being set that uid can replace it with a
// symlink, and os.Chmod follows one, Linux having no lchmod. Under an os.Root
// a name resolving outside the tree is refused instead.
//
// os.Lchown is already symlink-safe; it is inside the root for the confinement
// rather than for the follow.
func shareTree(root string, gid int, keep, sticky map[string]bool) (int, error) {
	dir, err := os.OpenRoot(root)
	if err != nil {
		return 0, err
	}
	defer func() { _ = dir.Close() }()

	changed := 0
	err = filepath.WalkDir(root, func(path string, entry os.DirEntry, err error) error {
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
		// Root's names are relative to it, and the root itself is ".".
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		// Asked before either operation and counted once: this is one path whether
		// it needs a regroup, a widen, or both.
		altered := wouldRegroup(info, gid)
		want := stickyIf(groupShared(info.Mode()), info.IsDir() && sticky[rel])
		if !keep[rel] && chmodBits(want) != chmodBits(info.Mode()) {
			altered = true
		}
		if altered {
			changed++
		}
		if err := dir.Lchown(rel, -1, gid); err != nil {
			return err
		}
		// Regrouped but not widened: its writer chose that mode, and widening it
		// here is a mode the writer narrows again on the next run.
		if keep[rel] {
			return nil
		}
		return dir.Chmod(rel, want)
	})
	return changed, err
}

// stickyDirs are the directories under the tree that hold a file an enrolment
// wrote, and so get the sticky bit. Sharing gives the client group rwx on
// every directory, and unlink and rename are permissions on the directory, so
// without this a brokered command can delete .claude/settings.json and put its
// own there whatever the file's mode. Sticky restricts unlink and rename to
// the file's owner.
//
// The tree's own root is deliberately not among them: sticky there would stop a
// brokered command renaming over any operator-owned file at the top level,
// which is what a tool rewriting a lock file by rename does. The cost is that
// a brokered command can move .claude aside and put its own directory there, so
// this narrows the window rather than closing it; `faramir doctor` reports a
// tree whose agent files no longer carry what the enrolment wrote.
func stickyDirs(keep []string) map[string]bool {
	out := make(map[string]bool, len(keep))
	for _, rel := range keep {
		if dir := filepath.Dir(filepath.Clean(rel)); dir != "." {
			out[dir] = true
		}
	}
	return out
}

// stickyIf adds the sticky bit to a directory in that set.
func stickyIf(mode os.FileMode, yes bool) os.FileMode {
	if !yes {
		return mode
	}
	return mode | os.ModeSticky
}

// chmodBits are the bits Chmod actually applies: the permissions, setuid,
// setgid and sticky. Whole modes would count ModeDir as a difference and call
// every run a change; the permissions alone would miss a setuid or sticky bit
// the chmod is about to clear.
func chmodBits(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// wouldRegroup and wouldReown report whether a chown to this id alters the
// path. A missing Stat_t answers "yes": over-reporting a change costs a report
// line, and under-reporting says a tree was left alone when it was not. A
// negative id is chown's "leave this as it is".
func wouldRegroup(info os.FileInfo, gid int) bool {
	if gid < 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return !ok || int(st.Gid) != gid
}

func wouldReown(info os.FileInfo, uid int) bool {
	if uid < 0 {
		return false
	}
	st, ok := info.Sys().(*syscall.Stat_t)
	return !ok || int(st.Uid) != uid
}

// groupShared is "chmod g+rwX", plus setgid on a directory. The X is why this
// is not a constant: a directory needs group execute to be entered, a file only
// when it was already executable for somebody. setgid is what makes it hold, a
// file either party creates inheriting the group.
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
// by the shared group. Execute only, never read, so these uids pass through
// without listing. Not "chmod o+x", which grants the same to every account on
// the machine.
func grantTraversal(home, dir string, opts Options, gid int) (int, error) {
	// Walked through descriptors rather than by path, as shareTree walks the tree:
	// these directories are the operator's, this runs as root, and os.Chmod and
	// os.Chown follow a link, so stat-ing a component and then chmodding it by
	// name resolves the path twice and would let root regroup a directory of the
	// agent's choosing.
	//
	// The home itself is opened O_NOFOLLOW and repaired through the descriptor;
	// everything under it is named inside an os.Root, which refuses a name
	// resolving outside the directory it was opened on.
	parts := components(home, dir)
	if len(parts) == 0 {
		// The tree is the home, so there is nothing above it to walk.
		return 0, nil
	}
	handle, err := os.OpenFile(home, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return 0, err
	}
	defer func() { _ = handle.Close() }()

	changed := 0
	apply := func(name string, info os.FileInfo, chown func() error, chmod func(os.FileMode) error) error {
		action, err := traversalAction(info, gid)
		if err != nil || action == leaveAlone {
			return err
		}
		if action == regroup {
			// The previous group loses whatever the group bits gave it.
			opts.logf("%s: group %s -> %s", name, groupName(info), opts.Group)
			if err := chown(); err != nil {
				return err
			}
		}
		if err := chmod(traversalMode(info.Mode(), action == regroup)); err != nil {
			return err
		}
		changed++
		opts.logf("%s: %s may now traverse it", name, opts.Group)
		return nil
	}

	info, err := handle.Stat()
	if err != nil {
		return changed, err
	}
	if err := apply(home, info,
		func() error { return handle.Chown(-1, gid) },
		handle.Chmod); err != nil {
		return changed, err
	}

	root, err := os.OpenRoot(home)
	if err != nil {
		return changed, err
	}
	defer func() { _ = root.Close() }()
	for _, component := range parts[1:] {
		name := filepath.Base(component)
		info, err := root.Stat(name)
		if err != nil {
			return changed, err
		}
		if err := apply(component, info,
			func() error { return root.Chown(name, -1, gid) },
			func(mode os.FileMode) error { return root.Chmod(name, mode) }); err != nil {
			return changed, err
		}
		next, err := root.OpenRoot(name)
		if err != nil {
			return changed, err
		}
		_ = root.Close()
		root = next
	}
	return changed, nil
}

// traversalMode is what one directory on the path is chmodded to: group execute
// added, and on a regroup the group's read and write dropped first, those bits
// having belonged to the previous group. The owner's own bits are never
// touched.
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
func traversalAction(info os.FileInfo, gid int) (traversal, error) {
	mode := info.Mode().Perm()
	// Already open to everyone. Tightening a directory the operator left open is
	// not this command's business.
	if mode&0o001 != 0 {
		return leaveAlone, nil
	}
	// Read off the same FileInfo the mode came from, rather than stat-ing the path
	// a second time.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return leaveAlone, errors.New("cannot read ownership")
	}
	if int(st.Gid) == gid {
		if mode&0o010 != 0 {
			return leaveAlone, nil
		}
		return addExecute, nil
	}
	return regroup, nil
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
