package hostfs

// Directories: creating them with the mode and ownership they must end up
// with, and reporting which of a list a run could not create or enter.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
)

// EnsureDir creates a directory if it is absent and asserts its mode and
// ownership if it is not. own=false leaves an existing one alone, for the
// directories the operator may have set up themselves.
func (f FS) EnsureDir(path string, mode os.FileMode, uid, gid int, own bool) (bool, error) {
	info, err := os.Stat(path)
	switch {
	// A dry run runs unprivileged and cannot answer for a directory it cannot
	// look inside. Reported as no change, so the rest is still produced.
	case f.DryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.DryRun {
			return true, nil
		}
		// Every directory MkdirAll creates, not just the leaf: an intermediate left
		// root-owned at 0700 is one its owner cannot traverse. The ancestors take
		// the ownership but not the mode: the secrets directory's 2770 applied to
		// its parent would hand write and rename on it to every brokered
		// command.
		created := missingAncestors(path)
		if err := os.MkdirAll(path, mode); err != nil {
			return false, err
		}
		for _, dir := range created {
			// MkdirAll applies the umask and ignores setgid.
			ancestorMode := os.FileMode(0o755)
			if dir == path {
				ancestorMode = mode
			}
			if err := os.Chmod(dir, ancestorMode); err != nil {
				return false, err
			}
			if err := chown(dir, uid, gid); err != nil {
				return false, err
			}
		}
		return true, nil
	case err != nil:
		return false, err
	case !info.IsDir():
		return false, fmt.Errorf("%s exists and is not a directory", path)
	}
	if !own {
		return false, nil
	}
	// The same rule as ensureOwnership: the mode and owner set below are what take
	// this directory back from the account the agent runs as, and through a link
	// they would land on its target. os.Stat above followed it; this does not.
	link, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symlink, and the mode and owner set here "+
			"would apply to its target: replace it with a real directory",
			path)
	}
	changed := info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid
	if wrong, err := WrongOwner(info, uid, gid); err != nil {
		return false, err
	} else if wrong {
		changed = true
	}
	if !changed || f.DryRun {
		return changed, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// RefuseUncreatableDirs is refuseUnenterableDirs for a home, where the writer
// asks a different question: an agent-file write calls EnsureDir on the leaf parent
// with own=false, which reads through a symlink deliberately, an agent's
// settings directory being wherever the operator keeps their dotfiles. Asking
// the stricter question here would refuse an install that then writes fine.
func RefuseUncreatableDirs(root string, mode os.FileMode, uid, gid int, paths []string) []string {
	var refused []string
	ask := FS{DryRun: true}
	for _, rel := range paths {
		dir := filepath.Dir(filepath.Join(root, rel))
		if dir == filepath.Clean(root) {
			continue
		}
		if _, err := ask.EnsureDir(dir, mode, uid, gid, false); err != nil {
			refused = append(refused, err.Error())
		}
	}
	return refused
}

// RefuseUnenterableDirs asks, of every directory these files sit in, the
// question creating it will ask: see EnsureDirsIn. A component that is a
// symlink is a directory a write would make outside root, which the caller's
// own refusal cannot answer for while the parent does not exist.
//
// Asked through a dry run, which answers and writes nothing, so both callers
// get it before what they do next cannot be undone: enrol before the
// share that walks the tree, and init before it hands files to the accounts.
// paths are relative to root, as the writers take them.
func RefuseUnenterableDirs(root string, mode os.FileMode, uid, gid int, paths []string) []string {
	var refused []string
	ask := FS{DryRun: true}
	for _, rel := range paths {
		dir := filepath.Dir(filepath.Join(root, rel))
		if err := ask.EnsureDirsIn(root, dir, mode, mode, uid, gid); err != nil {
			refused = append(refused, err.Error())
		}
	}
	return refused
}

// EnsureDirsIn creates every missing directory between root and path, each with
// mode and owner, and leaves the ones already there alone. The last component
// gets leafMode instead: it is the one that ends up holding a file, and in a
// tree that means the sticky bit, which the intermediate levels do not carry.
//
// Pinned to root rather than walked by path, unlike ensureDir: this runs as
// root in a tree the account the agent runs as can write, so a symlinked
// component would put a new directory outside the tree and hand it to the
// client group. An os.Root refuses to traverse a symlink at all, and the case
// below is what says which component is a link.
//
// A dry run answers the same question and writes nothing, which is what lets
// preflight ask it before the share that cannot be undone.
func (f FS) EnsureDirsIn(root, path string, mode, leafMode os.FileMode, uid, gid int) error {
	rel, err := filepath.Rel(root, path)
	if err != nil {
		return err
	}
	if rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%s is outside %s", path, root)
	}
	if rel == "." {
		return nil
	}
	handle, err := os.OpenRoot(root)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()

	at := ""
	parts := strings.Split(rel, string(filepath.Separator))
	for i, part := range parts {
		at = filepath.Join(at, part)
		here := filepath.Join(root, at)
		want := mode
		if i == len(parts)-1 {
			want = leafMode
		}
		// Lstat, so a symlink is seen as itself rather than as what it points at.
		info, err := handle.Lstat(at)
		switch {
		case err == nil && info.Mode()&os.ModeSymlink != 0:
			return fmt.Errorf("%s is a symlink, and a directory created inside it "+
				"would be created at its target, not in %s: replace it with a "+
				"real directory", here, root)
		case err == nil && info.IsDir():
			// The project's own, and not this command's to re-own: the share settles
			// the mode of a directory that was already there.
			continue
		case err == nil:
			return fmt.Errorf("%s exists and is not a directory", here)
		case !errors.Is(err, os.ErrNotExist):
			return err
		}
		if f.DryRun {
			// Nothing below it can be there either, so there is nothing left to
			// ask.
			return nil
		}
		if err := handle.Mkdir(at, want.Perm()); err != nil {
			return err
		}
		// Mkdir applies the umask and ignores setgid and sticky, as MkdirAll does.
		if err := handle.Chmod(at, want); err != nil {
			return err
		}
		if uid != Keep || gid != Keep {
			if err := handle.Lchown(at, uid, gid); err != nil {
				return err
			}
		}
	}
	return nil
}

// EnsureOwnership fixes an existing file's owner, group and mode without
// touching its contents. Lstat to decide and a descriptor to repair, never a
// path-based chmod: the directories this walks are writable by the account the
// assertion exists to constrain, so a symlink planted there would take root's
// chmod to its target.
func (f FS) EnsureOwnership(path string, mode os.FileMode, uid, gid int) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Blocked rather than skipped: the mode and owner asserted here are what
		// keep the file out of the agent's reach.
		return false, fmt.Errorf("%s is a symlink, and its mode and owner would be "+
			"applied to its target: replace it with a regular file", path)
	}
	wrong, err := WrongOwner(info, uid, gid)
	if err != nil {
		return false, err
	}
	if info.Mode().Perm() == mode.Perm() && !wrong {
		return false, nil
	}
	if f.DryRun {
		return true, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// EnsurePrivateFile creates an empty 0600 file if it is absent and asserts its
// mode and ownership either way, for a file whose owner would otherwise be
// whichever uid writes to it first. 0600 rather than a parameter: the one
// thing this creates is the audit log.
func (f FS) EnsurePrivateFile(path string, uid, gid int) (bool, error) {
	const mode = os.FileMode(0o600)
	switch _, err := os.Lstat(path); {
	// A dry run runs unprivileged and cannot look inside a directory the broker
	// owns. Reported as no change, as ensureDir does.
	case f.DryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.DryRun {
			return true, nil
		}
		handle, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
		if err != nil {
			return false, err
		}
		_ = handle.Close()
		// The open applied the umask to mode; this does not.
		return true, chmodAndChown(path, mode, uid, gid)
	case err != nil:
		return false, err
	}
	return f.EnsureOwnership(path, mode, uid, gid)
}

// chmodAndChown repairs one file through a descriptor opened O_NOFOLLOW, so the
// file checked and the file changed are the same file even if the path is
// re-pointed in between. O_NONBLOCK so a fifo does not wait for a writer.
func chmodAndChown(path string, mode os.FileMode, uid, gid int) error {
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Chmod(mode); err != nil {
		return err
	}
	if uid == Keep && gid == Keep {
		return nil
	}
	return handle.Chown(uid, gid)
}
