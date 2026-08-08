package install

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"syscall"
)

// keep is the uid or gid value that leaves ownership as it is.
const keep = -1

// fsys is the filesystem side of an install.  Every method reports whether it
// changed anything, which is what makes a run's output usable by a
// configuration manager: the scripts this replaces printed prose, so the caller
// had to stat the host before and after and guess.
//
// With dryRun set each method computes the same answer and writes nothing.
type fsys struct{ dryRun bool }

// ensureDir creates a directory if it is absent and asserts its mode and
// ownership if it is not.
//
// own=false leaves an existing directory's mode and ownership alone.  That is
// for the ones the operator may have set up themselves: a config directory
// inside their own home comes back root-owned and no longer theirs to edit if
// this re-applies to it unconditionally.
func (f fsys) ensureDir(path string, mode os.FileMode, uid, gid int, own bool) (bool, error) {
	info, err := os.Stat(path)
	switch {
	// A dry run is the one case that legitimately runs unprivileged, and a
	// directory it cannot look inside is one it cannot answer for.  Reported as
	// no change rather than as a failure, so the rest of the report still gets
	// produced.
	case f.dryRun && errors.Is(err, os.ErrPermission):
		return false, nil
	case errors.Is(err, os.ErrNotExist):
		if f.dryRun {
			return true, nil
		}
		// Every directory MkdirAll has to create, not just the leaf.  An
		// intermediate left root-owned at the leaf's mode is a path its owner
		// cannot traverse: ~/.config/sops created 0700 root:root puts the
		// operator's own age identity out of their reach, and sops then reports
		// only that it found no key.
		created := missingAncestors(path)
		if err := os.MkdirAll(path, mode); err != nil {
			return false, err
		}
		for _, dir := range created {
			// MkdirAll applies the umask and ignores setgid, so the mode is set
			// again explicitly.
			if err := os.Chmod(dir, mode); err != nil {
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
	changed := info.Mode().Perm() != mode.Perm() || info.Mode()&os.ModeSetgid != mode&os.ModeSetgid
	if wrong, err := wrongOwner(info, uid, gid); err != nil {
		return false, err
	} else if wrong {
		changed = true
	}
	if !changed || f.dryRun {
		return changed, nil
	}
	if err := os.Chmod(path, mode); err != nil {
		return false, err
	}
	return true, chown(path, uid, gid)
}

// writeFile writes data when the file is absent or its contents differ.
// Compared by content rather than by mtime so a re-run of an unchanged install
// reports nothing.
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
	// Written to a temporary file and renamed, never truncated in place: a
	// failed write would otherwise leave an empty config behind, and a caller
	// that keeps whatever it finds would preserve it forever.
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

// remove deletes a path, reporting whether there was anything to delete.
func (f fsys) remove(path string) (bool, error) {
	if _, err := os.Lstat(path); errors.Is(err, os.ErrNotExist) {
		return false, nil
	} else if err != nil {
		return false, err
	}
	if f.dryRun {
		return true, nil
	}
	return true, os.RemoveAll(path)
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

// probe is exists with a third answer.  known is false when the question cannot
// be settled without more privilege than the caller has, which happens only
// under a dry run: the real thing runs as root and can stat anything.  Reporting
// "not there" for a key sitting behind a 0700 directory would tell an operator
// their key is about to be regenerated when it is not.
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

// lookupUser and lookupGroup resolve a name to an id.  Separated from the steps
// that use them so a missing account is reported as the account it is rather
// than as whatever the next syscall returned.
func lookupUser(name string) (int, error) {
	entry, err := user.Lookup(name)
	if err != nil {
		return 0, fmt.Errorf("no such user %q: %w", name, err)
	}
	return strconv.Atoi(entry.Uid)
}

func lookupGroup(name string) (int, error) {
	entry, err := user.LookupGroup(name)
	if err != nil {
		return 0, fmt.Errorf("no such group %q: %w", name, err)
	}
	return strconv.Atoi(entry.Gid)
}

// userExists and groupExists answer without turning a missing entry into an
// error, which is what the account step needs to decide whether to create one.
func userExists(name string) bool {
	_, err := user.Lookup(name)
	return err == nil
}

func groupExists(name string) bool {
	_, err := user.LookupGroup(name)
	return err == nil
}
