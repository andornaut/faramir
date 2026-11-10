package sharetree

// Whether the group can reach a shared path at all: the directories above it
// that stop it, and who is asked.

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
)

// Blocker is one directory above a shared path that the group cannot enter,
// with the group and mode that stop it.
type Blocker struct {
	Path      string
	Group     string
	Mode      os.FileMode
	AccessACL bool
}

// Traversable reports which directories from the filesystem root down to the
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
	_, err = user.Lookup(opts.Operator)
	if err != nil {
		return nil, noSuchUser(opts.Operator, err)
	}
	group, err := user.LookupGroup(opts.Group)
	if err != nil {
		return nil, noSuchGroup(opts.Group, err)
	}
	gid, _ := strconv.Atoi(group.Gid)
	who := groupEntrant(gid)
	if opts.Account != "" {
		who, err = entrantFor(opts.Account, gid)
		if err != nil {
			return nil, err
		}
	}
	return blockers(string(filepath.Separator), dir, who)
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
		return entrant{}, noSuchUser(account, err)
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
// This is the fallback for a filesystem without an access ACL. CAP_DAC_OVERRIDE
// is not considered: this asks about an ordinary account or a group.
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
// per line, each indented to sit under the message that names them. A directory already in the group needs the execute bit alone; one
// in another group is regrouped first, and "g=x" rather than "g+x" because the
// read and write bits there belonged to the group being replaced.
func Fix(blocked []Blocker, group string) string {
	lines := make([]string, 0, len(blocked))
	for _, b := range blocked {
		if b.AccessACL {
			lines = append(lines, fmt.Sprintf("  grant group %s search (x) in the access ACL on %s, including its mask", group, b.Path))
			continue
		}
		if b.Group == group {
			lines = append(lines, "  sudo chmod g+x "+b.Path)
			continue
		}
		lines = append(lines, fmt.Sprintf("  sudo chgrp %s %s && sudo chmod g=x %s",
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

// components lists every directory from the starting root to dir's parent, the tree
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

// blockers is every directory from the starting root down to the tree that the group
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
	add := func(name string, directory *os.File) error {
		info, err := directory.Stat()
		if err != nil {
			return err
		}
		allowed, accessACL, err := canTraverse(who, info, directory)
		if err != nil || allowed {
			return err
		}
		found = append(found, Blocker{
			Path: name, Group: groupName(info), Mode: info.Mode().Perm(), AccessACL: accessACL,
		})
		return nil
	}

	if err := add(home, handle); err != nil {
		return nil, err
	}

	root, err := os.OpenRoot(home)
	if err != nil {
		return nil, err
	}
	defer func() { _ = root.Close() }()
	for _, component := range parts[1:] {
		name := filepath.Base(component)
		directory, err := root.OpenFile(name, os.O_RDONLY|syscall.O_DIRECTORY, 0)
		if err != nil {
			return nil, err
		}
		err = add(component, directory)
		_ = directory.Close()
		if err != nil {
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
