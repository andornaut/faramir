// Package sharetree makes one directory usable by brokered commands.
//
//	shared     group-owned and setgid, so the operator and a brokered command
//	           do not fight over every file either creates (with umask 002)
//	reachable  a home is 0700, so every directory above the tree has to be
//	           group-executable by a group the executor is in
//
// Only the first is applied here. The directories above the tree belong to the
// operator, so Traversable reports the ones that block the group and alters
// nothing; whoever manages the host's permissions sets them.
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
	"slices"
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
	// Account, when set, is who has to get there, rather than which group does.
	// Traversable then asks the kernel's question -- owner, then any group the
	// account is in, then other -- so a directory already open to the account
	// another way is not a blocker. Group is still the one a remedy names.
	//
	// Set where the caller knows which account has to reach a path: the broker
	// reaching a linked file is one account, and it is in more than one group.
	// Left empty where the question really is about the group, as it is for a
	// tree three accounts share.
	Account string
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
	// Changed is how many paths in the tree this run regrouped or rechmodded.
	Changed int
	// Sticky and Kept are what the share held back rather than widened: the
	// directories restricted to their owner for unlink and rename, and the files
	// left at the mode their writer chose. Reported because they are the part of
	// a share that is not "everything became group-writable".
	Sticky int
	Kept   int
}

// Share regroups and widens one directory and everything under it. Whether the
// group can reach it is the other half and is not applied here: Traversable
// answers that, and the directories above the tree are not this command's to
// alter.
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
	result.Sticky = len(sticky)
	// Kept counts the files found, not the list: a keep path not there yet is
	// nothing this run left at its own mode.
	for rel := range keep {
		if _, err := os.Lstat(filepath.Join(dir, rel)); err == nil {
			result.Kept++
		}
	}
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
	return result, nil
}

// Blocker is one directory above a shared path that the group cannot enter,
// with the group and mode that stop it.
type Blocker struct {
	Path  string
	Group string
	Mode  os.FileMode
}

// Traversable reports which directories from the operator's home down to the
// path named the group cannot enter, and alters none of them. Empty means the
// group can already reach it. With Options.Account set the question is asked
// about that account instead; see the field.
//
// The last component is left out of the question, because whatever names it
// grants it: Share sets the tree it is about to share, and a link's own file is
// asked about as a file. So a caller asking about the directories that hold a
// file names the file, and one naming a directory is answered about everything
// above it and not about the directory itself.
func Traversable(opts Options) ([]Blocker, error) {
	dir, err := Resolve(opts.Dir)
	if err != nil {
		return nil, err
	}
	owner, err := user.Lookup(opts.Operator)
	if err != nil {
		return nil, fmt.Errorf("no such user %q: %w", opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return nil, fmt.Errorf("no such group %q: %w", opts.Group, err)
	}
	gid, _ := strconv.Atoi(group.Gid)
	// Outside the homes the modes already allow it.
	home := resolvedHome(owner)
	if home == "" || !within(home, dir) {
		return nil, nil
	}
	who := groupEntrant(gid)
	if opts.Account != "" {
		who, err = entrantFor(opts.Account, gid)
		if err != nil {
			return nil, err
		}
	}
	return blockers(home, dir, who)
}

// entrant is who has to get in: a uid, or -1 where the caller asked about a
// group and no account owns the question, and every gid that counts.
type entrant struct {
	uid  int
	gids []int
}

// groupEntrant is the question asked about a group alone, where the owner bits
// answer for nobody the caller is speaking for.
func groupEntrant(gid int) entrant { return entrant{uid: -1, gids: []int{gid}} }

// entrantFor is the account's own uid and groups, with the group a remedy would
// name folded in: a dry run against a group nobody is in yet still reports what
// that group would open.
func entrantFor(account string, gid int) (entrant, error) {
	entry, err := user.Lookup(account)
	if err != nil {
		return entrant{}, fmt.Errorf("no such user %q: %w", account, err)
	}
	uid, _ := strconv.Atoi(entry.Uid)
	who := entrant{uid: uid, gids: []int{gid}}
	ids, err := entry.GroupIds()
	if err != nil {
		return entrant{}, err
	}
	for _, id := range ids {
		n, convErr := strconv.Atoi(id)
		if convErr != nil {
			continue
		}
		if !slices.Contains(who.gids, n) {
			who.gids = append(who.gids, n)
		}
	}
	return who, nil
}

// canEnter reports whether this account may traverse a directory at that
// ownership and mode: the kernel's own order, owner then group then other.
// ACLs and CAP_DAC_OVERRIDE are not read, so this is the answer for an
// ordinary account on an ordinary filesystem.
func (e entrant) canEnter(st *syscall.Stat_t, mode os.FileMode) bool {
	if e.uid >= 0 && int(st.Uid) == e.uid {
		return mode&0o100 != 0
	}
	if slices.Contains(e.gids, int(st.Gid)) {
		return mode&0o010 != 0
	}
	return mode&0o001 != 0
}

// Fix is what the operator runs to open the reported directories, one command
// per line. A directory already in the group needs the execute bit alone; one
// in another group is regrouped first, and "g=x" rather than "g+x" because the
// read and write bits there belonged to the group being replaced.
func Fix(blocked []Blocker, group string) string {
	lines := make([]string, 0, len(blocked))
	for _, b := range blocked {
		if b.Group == group {
			lines = append(lines, "sudo chmod g+x "+b.Path)
			continue
		}
		lines = append(lines, fmt.Sprintf("sudo chgrp %s %s && sudo chmod g=x %s",
			group, b.Path, b.Path))
	}
	return strings.Join(lines, "\n")
}

// Describe names the reported directories with what is on them now, for a
// message that has already said what is wrong.
func Describe(blocked []Blocker) string {
	out := make([]string, 0, len(blocked))
	for _, b := range blocked {
		out = append(out, fmt.Sprintf("%s (%s, %04o)", b.Path, b.Group, b.Mode))
	}
	return strings.Join(out, ", ")
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

// blockers is every directory from the home down to the tree that the group
// cannot enter. Nothing is altered: these directories are the operator's.
//
// Walked through descriptors rather than by path, as shareTree walks the tree:
// this runs as root over paths the agent's uid can replace, so resolving a name
// once to stat it and again to report it can answer about two different
// directories.
func blockers(home, dir string, who entrant) ([]Blocker, error) {
	parts := components(home, dir)
	if len(parts) == 0 {
		// The tree is the home, so there is nothing above it to walk.
		return nil, nil
	}
	handle, err := os.OpenFile(home, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_DIRECTORY, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = handle.Close() }()

	var found []Blocker
	add := func(name string, info os.FileInfo) error {
		action, err := traversalAction(info, who)
		if err != nil || action == leaveAlone {
			return err
		}
		found = append(found, Blocker{
			Path: name, Group: groupName(info), Mode: info.Mode().Perm(),
		})
		return nil
	}

	info, err := handle.Stat()
	if err != nil {
		return nil, err
	}
	if err := add(home, info); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, component := range parts[1:] {
		name := filepath.Base(component)
		info, err := root.Stat(name)
		if err != nil {
			return nil, err
		}
		if err := add(component, info); err != nil {
			return nil, err
		}
		next, err := root.OpenRoot(name)
		if err != nil {
			return nil, err
		}
		_ = root.Close()
		root = next
	}
	return found, nil
}

type traversal int

const (
	leaveAlone traversal = iota
	addExecute
	regroup
)

// traversalAction decides what one directory on the path needs. Nothing, where
// whoever was asked about can already enter it: tightening a directory the
// operator left open is not this command's business, and neither is regrouping
// one that is already open to the account another way.
func traversalAction(info os.FileInfo, who entrant) (traversal, error) {
	mode := info.Mode().Perm()
	// Read off the same FileInfo the mode came from, rather than stat-ing the path
	// a second time.
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return leaveAlone, errors.New("cannot read ownership")
	}
	if who.canEnter(st, mode) {
		return leaveAlone, nil
	}
	// Blocked. The remedy is the execute bit alone where the group a fix would
	// name already owns it, and a regroup otherwise.
	if len(who.gids) > 0 && int(st.Gid) == who.gids[0] {
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
