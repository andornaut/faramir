package vault

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/hostfs"
)

// withPublicationLock serializes cooperating writers' final check and mutation
// on one directory inode. Closing releases the lock, including after a crash.
// Direct writes by tools that do not take this advisory lock are not covered.
func withPublicationLock(publish func() error, target string) error {
	dir, err := os.Open(filepath.Dir(target))
	if err != nil {
		return err
	}
	defer func() { _ = dir.Close() }()
	if err := unix.Flock(int(dir.Fd()), unix.LOCK_EX); err != nil {
		return fmt.Errorf("cannot lock publication directory %s: %w", filepath.Dir(target), err)
	}
	defer func() { _ = unix.Flock(int(dir.Fd()), unix.LOCK_UN) }()
	return publish()
}

// RemovalSnapshot keeps the inspected identity and ciphertext digest private;
// only ref names and a value-free parsing problem are reported to the operator.
type RemovalSnapshot struct {
	Refs    []string
	RefsErr error
	path    string
	entry   os.FileInfo
	file    os.FileInfo
	digest  [sha256.Size]byte
}

// InspectRemoval reads ref names and the removal guard from one ciphertext
// snapshot before confirmation. An unreadable or non-regular file is refused.
func InspectRemoval(target string) (*RemovalSnapshot, error) {
	entry, err := os.Lstat(target)
	if err != nil {
		return nil, err
	}
	// NONBLOCK prevents a concurrent substitution of a FIFO from hanging this
	// inspection. The descriptor is checked before any bytes are read.
	file, err := os.OpenFile(target, os.O_RDONLY|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, fmt.Errorf("%s is not a regular managed file", target)
	}
	body, err := io.ReadAll(file)
	if err != nil {
		return nil, err
	}
	refs, refsErr := refsIn(body)
	if refsErr != nil {
		// YAML errors can quote input. A removal prompt reports no values.
		refsErr = errors.New("does not parse as a managed document")
	}
	return &RemovalSnapshot{
		Refs: refs, RefsErr: refsErr, path: target,
		entry: entry, file: info, digest: sha256.Sum256(body),
	}, nil
}

// Remove refuses a changed snapshot, even when the CLI skipped confirmation.
// The recheck and unlink are protected from cooperating Faramir publications.
func (s *RemovalSnapshot) Remove() error {
	return withPublicationLock(func() error {
		now, err := InspectRemoval(s.path)
		if err != nil {
			return err
		}
		if !os.SameFile(s.entry, now.entry) || !os.SameFile(s.file, now.file) || s.digest != now.digest {
			return fmt.Errorf("%s changed while removal was awaiting confirmation; nothing was removed. Run this again", s.path)
		}
		if err := os.Remove(s.path); err != nil {
			return err
		}
		if err := hostfs.SyncDir(filepath.Dir(s.path)); err != nil {
			fmt.Fprintf(os.Stderr, "faramir: %s was removed, but its directory could not be flushed (%v), so removal may not survive a power loss\n", s.path, err)
		}
		return nil
	}, s.path)
}
