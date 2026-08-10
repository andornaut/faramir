package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// keep is the uid or gid value that leaves ownership as it is.
const keep = -1

// fsys is the filesystem side of an install.  Every method reports whether it
// changed anything, so a configuration manager need not stat the host before
// and after.  With dryRun set each computes the same answer and writes nothing.
type fsys struct{ dryRun bool }

// ensureDir creates a directory if it is absent and asserts its mode and
// ownership if it is not.  own=false leaves an existing one alone, for the
// directories the operator may have set up themselves.
func (f fsys) ensureDir(path string, mode os.FileMode, uid, gid int, own bool) (bool, error) {
	info, err := os.Stat(path)
	switch {
	// A dry run runs unprivileged and cannot answer for a directory it cannot look
	// inside.  Reported as no change, so the rest still gets produced.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.dryRun {
			return true, nil
		}
		// Every directory MkdirAll creates, not just the leaf: an intermediate left
		// root-owned at 0700 is one its owner cannot traverse.
		//
		// The ancestors take the ownership but not the mode, 0755 being traversal and
		// nothing more: the secrets directory's 2770 applied to its parent would hand
		// write and rename on the secrets directory to every brokered command.
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
	// Asserted from here down, so the same rule as ensureOwnership applies: the
	// mode and owner set below are what take this directory back from the account
	// the agent runs as, and through a link they would land on its target while
	// the link kept its own ownership.  os.Stat above followed it; this does not.
	link, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if link.Mode()&os.ModeSymlink != 0 {
		return false, fmt.Errorf("%s is a symlink, and the mode and owner asserted "+
			"here would land on whatever it points at: replace it with a real directory",
			path)
	}
	changed := info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid
	if wrong, err := wrongOwner(info, uid, gid); err != nil {
		return false, err
	} else if wrong {
		changed = true
	}
	if !changed || f.dryRun {
		return changed, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// ensureOwnership fixes an existing file's owner, group and mode without
// touching its contents, for a file only its owner can read.
//
// Lstat to decide and a descriptor to repair, never a path-based chmod: the
// directories this walks are writable by the account the assertion exists to
// constrain, so a symlink planted there would take root's chmod to its target.
func (f fsys) ensureOwnership(path string, mode os.FileMode, uid, gid int) (bool, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		// Refused rather than skipped: the mode and owner asserted here are what
		// keeps the file out of the agent's reach, and a link left in place is one
		// whose target the agent may own.  Replace it with a regular file.
		return false, fmt.Errorf("%s is a symlink, and its mode and owner would be "+
			"applied to whatever it points at: replace it with a regular file", path)
	}
	wrong, err := wrongOwner(info, uid, gid)
	if err != nil {
		return false, err
	}
	if info.Mode().Perm() == mode.Perm() && !wrong {
		return false, nil
	}
	if f.dryRun {
		return true, nil
	}
	return true, chmodAndChown(path, mode, uid, gid)
}

// ensurePrivateFile creates an empty 0600 file if it is absent and asserts its
// mode and ownership either way, for a file whose owner would otherwise be
// whichever uid happens to write to it first.  0600 rather than a parameter:
// the one thing this creates is the audit log, and a mode that let another
// account read it would undo what the separate uid is for.
func (f fsys) ensurePrivateFile(path string, uid, gid int) (bool, error) {
	const mode = os.FileMode(0o600)
	switch _, err := os.Lstat(path); {
	// A dry run runs unprivileged and cannot look inside a directory the broker
	// owns.  Reported as no change, as ensureDir does.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.dryRun {
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
	return f.ensureOwnership(path, mode, uid, gid)
}

// chmodAndChown repairs one file through a descriptor opened O_NOFOLLOW, so
// the file checked and the file changed are the same file even if the path is
// re-pointed in between.  O_NONBLOCK so a fifo does not wait for a writer.
func chmodAndChown(path string, mode os.FileMode, uid, gid int) error {
	handle, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return err
	}
	defer func() { _ = handle.Close() }()
	if err := handle.Chmod(mode); err != nil {
		return err
	}
	if uid == keep && gid == keep {
		return nil
	}
	return handle.Chown(uid, gid)
}

// mergeFile merges faramir's keys into an existing JSON file, or writes data
// whole.  Handed to writeFile, so it is owned and renamed the same way.
func (f fsys) mergeFile(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	current, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return f.writeFile(path, data, mode, uid, gid)
	case err != nil:
		return false, err
	}
	merged, err := mergeJSON(current, data)
	if err != nil {
		return false, fmt.Errorf("%s: %w", path, err)
	}
	return f.writeFile(path, merged, mode, uid, gid)
}

// writeFile writes data when the file is absent or differs.  Compared by
// content, so an unchanged re-run reports nothing.
func (f fsys) writeFile(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	current, err := os.ReadFile(path)
	if err == nil && bytes.Equal(current, data) {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return false, statErr
		}
		wrong, ownErr := wrongOwner(info, uid, gid)
		if ownErr != nil {
			return false, ownErr
		}
		if info.Mode().Perm() == mode.Perm() && !wrong {
			return false, nil
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if f.dryRun {
		return true, nil
	}
	// Written and renamed, never truncated in place: a failed write would leave an
	// empty config that a caller keeping what it finds preserves forever.
	tmp, err := os.CreateTemp(filepath.Dir(path), filepath.Base(path)+".*")
	if err != nil {
		return false, err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return false, err
	}
	if err := tmp.Close(); err != nil {
		return false, err
	}
	if err := os.Chmod(tmp.Name(), mode); err != nil {
		return false, err
	}
	if err := chown(tmp.Name(), uid, gid); err != nil {
		return false, err
	}
	return true, os.Rename(tmp.Name(), path)
}

// copyFile writes src's contents to dst under dst's own mode and ownership.
func (f fsys) copyFile(src, dst string, mode os.FileMode, uid, gid int) (bool, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	return f.writeFile(dst, data, mode, uid, gid)
}

// missingAncestors lists every directory MkdirAll would have to create, from
// the shallowest down to path itself.
func missingAncestors(path string) []string {
	var missing []string
	for at := path; ; at = filepath.Dir(at) {
		if exists(at) {
			break
		}
		missing = append([]string{at}, missing...)
		if parent := filepath.Dir(at); parent == at {
			break
		}
	}
	return missing
}

// exists reports whether a path is there, following symlinks.
func exists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// probe is exists with a third answer: known is false when the question needs
// more privilege than the caller has, which only happens under a dry run. "not
// there" for a key behind a 0700 directory would read as a key about to be
// regenerated.
func probe(path string) (present, known bool) {
	switch _, err := os.Stat(path); {
	case err == nil:
		return true, true
	case errors.Is(err, os.ErrNotExist):
		return false, true
	default:
		return false, false
	}
}

func chown(path string, uid, gid int) error {
	if uid == keep && gid == keep {
		return nil
	}
	return os.Lchown(path, uid, gid)
}

func wrongOwner(info os.FileInfo, uid, gid int) (bool, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return false, errors.New("cannot read ownership")
	}
	if uid != keep && int(stat.Uid) != uid {
		return true, nil
	}
	return gid != keep && int(stat.Gid) != gid, nil
}

func deviceOf(info os.FileInfo) uint64 {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0
	}
	return stat.Dev
}

// lookupUser and lookupGroup resolve a name to an id, so a missing account is
// reported as itself rather than as whatever the next syscall returned.
func lookupUser(name string) (int, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("no such user %q: %w", name, err)
	}
	return strconv.Atoi(entry.Uid)
}

// lookPathOr resolves a program on PATH, falling back to a conventional path so
// a host that has it somewhere unusual still gets an absolute path, and one
// that lacks it gets a config naming where it should be.  The broker refuses to
// start when the binary is not there, which is where that is reported.
func lookPathOr(program, fallback string) string {
	if path, err := exec.LookPath(program); err == nil {
		return path
	}
	return fallback
}

// primaryGroup resolves an account's own group, returning both the gid and the
// name.  Two lookups rather than one on the account name, which would find a
// group that merely shares the name.
func primaryGroup(account string) (int, string, error) {
	entry, err := user.Lookup(account)
	if err != nil {
		return 0, "", fmt.Errorf("no such user %q: %w", account, err)
	}
	gid, err := strconv.Atoi(entry.Gid)
	if err != nil {
		return 0, "", err
	}
	group, err := user.LookupGroupId(entry.Gid)
	if err != nil {
		return 0, "", fmt.Errorf("%s has no group %s: %w", account, entry.Gid, err)
	}
	return gid, group.Name, nil
}

func lookupGroup(name string) (int, error) {
	entry, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no such group %q: %w", name, err)
	}
	return strconv.Atoi(entry.Gid)
}

// userExists and groupExists answer without turning a missing entry into an
// error.
func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func groupExists(name string) bool {
	_, err := user.LookupGroup(name)
	return err == nil
}
