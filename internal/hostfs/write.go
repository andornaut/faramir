package hostfs

// Writing a file, and refusing a write onto content the caller never read.

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
)

// writeInto is writeFile relative to an open directory: same comparison, same
// temp-and-rename, and no path resolved twice. The temp is created O_EXCL, so
// one already sitting there is an error rather than something to truncate.
func (f FS) writeInto(root *os.Root, name string, data []byte, mode os.FileMode,
	uid, gid int, prior PriorState) (bool, error) {
	current, err := root.ReadFile(name)
	if err == nil && bytes.Equal(current, data) {
		info, statErr := root.Stat(name)
		if statErr != nil {
			return false, statErr
		}
		wrong, ownErr := WrongOwner(info, uid, gid)
		if ownErr != nil {
			return false, ownErr
		}
		if info.Mode().Perm() == mode.Perm() && !wrong {
			return false, nil
		}
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	if f.DryRun {
		return true, nil
	}
	tmp := name + ".faramir-tmp"
	handle, err := root.OpenFile(tmp, os.O_CREATE|os.O_EXCL|os.O_WRONLY, mode)
	if errors.Is(err, os.ErrExist) {
		// O_EXCL, so one already there is not something to truncate: it is either
		// a run in progress or what a killed one left, and neither is this write's
		// to overwrite. Named through the root's own path and wrapped: the bare
		// error says a file exists without saying which, and tmp is a base name
		// whose directory is the one thing an operator cannot guess.
		return false, fmt.Errorf("%s is already there, so nothing was written: it is "+
			"the temporary file a write goes through, so another faramir command is "+
			"writing this file, or one was interrupted while it did. Run them one at "+
			"a time; delete it if none is running: %w",
			filepath.Join(root.Name(), tmp), err)
	}
	if err != nil {
		return false, fmt.Errorf("%s: %w", tmp, err)
	}
	// Removed only where the rename did not take it. After a successful rename the
	// name is free, and another writer's O_EXCL open may already have claimed it:
	// removing it then deletes that run's temporary file, and its chmod fails with
	// an ENOENT about a path it created itself.
	renamed := false
	defer func() {
		if !renamed {
			_ = root.Remove(tmp)
		}
	}()
	// Asked while the temporary name is held, which is what makes it decide
	// something: O_EXCL admits one writer at a time, so a second either fails
	// above or gets here after the first has renamed and sees the change. Asked
	// before the write rather than after, so nothing is written for a rename that
	// is not going to happen.
	if err := unchangedFrom(root, name, prior); err != nil {
		return false, err
	}
	if _, err := handle.Write(data); err != nil {
		_ = handle.Close()
		return false, err
	}
	if err := handle.Close(); err != nil {
		return false, err
	}
	// The open applied the umask; these do not.
	if err := root.Chmod(tmp, mode); err != nil {
		return false, err
	}
	if uid != Keep || gid != Keep {
		if err := root.Lchown(tmp, uid, gid); err != nil {
			return false, err
		}
	}
	if err := root.Rename(tmp, name); err != nil {
		return false, err
	}
	renamed = true
	return true, nil
}

// PriorState is what the caller found when it read the file it is now writing
// back. Two things, and they are refused differently: a file something else
// rewrote, and a file something else created where this caller found none.
//
// Absence has to be one of them. A record's first write has no digest to
// expect, so treating "nothing to compare" as "nothing to check" left two
// concurrent first runs both writing and one entry lost with no error, which
// is the window the digest exists to close.
type PriorState struct {
	// digest is the sha256 of what was there, nil where nothing was.
	digest []byte
	// read is whether the caller looked at all. A write that is not an edit of
	// anything sets neither field and is refused for nothing, which is most of
	// them.
	read bool
}

// Unread is the state of a write that is not an edit: nothing was read, so
// nothing is expected.
func Unread() PriorState { return PriorState{} }

// After is the state of a caller that read the file, digest or not.
func After(digest []byte) PriorState { return PriorState{digest: digest, read: true} }

// unchangedFrom refuses a write onto a file something else has written, or
// created, since the caller read.
func unchangedFrom(root *os.Root, name string, prior PriorState) error {
	if !prior.read {
		return nil
	}
	body, err := root.ReadFile(name)
	switch {
	case errors.Is(err, os.ErrNotExist):
		// Gone, or never there. Either matches a caller that read nothing.
		if prior.digest == nil {
			return nil
		}
	case err != nil:
		return err
	case prior.digest == nil:
		// The caller read no file and one is here now: another run created it,
		// and renaming over it would take whatever it wrote.
		return fmt.Errorf("%s was created while this was working on it, so nothing "+
			"was written: another faramir command wrote it first. Run them one at a "+
			"time, then run this again", filepath.Join(root.Name(), name))
	default:
		sum := sha256.Sum256(body)
		if bytes.Equal(sum[:], prior.digest) {
			return nil
		}
	}
	return fmt.Errorf("%s changed while this was working on it, so nothing was "+
		"written: another faramir command edited it. Run them one at a time, then "+
		"run this again", filepath.Join(root.Name(), name))
}

// OwnerOf is a file's uid and gid, or keep for both where they cannot be read.
func OwnerOf(info os.FileInfo) (int, int) {
	st, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return Keep, Keep
	}
	return int(st.Uid), int(st.Gid)
}

// WriteFile writes data when the file is absent or differs, compared by content
// so an unchanged re-run reports nothing.
//
// Through a descriptor opened on the parent, so the directory is resolved once
// and the temp and the rename cannot land in two different places: some of what
// this writes sits in the agent account's home or in an enrolled tree, which an
// account other than root can replace while a run is in progress.
func (f FS) WriteFile(path string, data []byte, mode os.FileMode, uid, gid int) (bool, error) {
	return f.WriteFileWith(path, data, mode, uid, gid, Unread())
}

// WriteFileExpecting is writeFile for a file the caller read and is writing
// back: the write is refused where something else has written it since, and
// where something else created one the caller did not find. expect is the
// digest of what was read, nil where nothing was there. Ownership is kept,
// every caller writing a file the install already owns.
func (f FS) WriteFileExpecting(path string, data []byte, mode os.FileMode,
	expect []byte) (bool, error) {
	return f.WriteFileWith(path, data, mode, Keep, Keep, After(expect))
}

// WriteFileWith is both, against the prior state the caller asserts.
func (f FS) WriteFileWith(path string, data []byte, mode os.FileMode,
	uid, gid int, prior PriorState) (bool, error) {
	root, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		// A dry run creates no directories, so the parent of a file it would create
		// is not there to open. Reported as a write.
		if f.DryRun {
			return true, nil
		}
		return false, err
	}
	defer func() { _ = root.Close() }()
	return f.writeInto(root, filepath.Base(path), data, mode, uid, gid, prior)
}

// CopyFile writes src's contents to dst under dst's own mode and ownership.
func (f FS) CopyFile(src, dst string, mode os.FileMode, uid, gid int) (bool, error) {
	data, err := os.ReadFile(src)
	if err != nil {
		return false, err
	}
	return f.WriteFile(dst, data, mode, uid, gid)
}

// SyncDir flushes a directory entry, which is what makes a create or a rename
// survive a power loss rather than only a process dying. Not done by the writes
// above: what they write, an install rewrites, and a file that cannot be
// regenerated is the caller's to make durable.
func SyncDir(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return err
	}
	if err := dir.Sync(); err != nil {
		_ = dir.Close()
		return err
	}
	return dir.Close()
}
