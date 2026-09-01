package auditview

// Following the log across a rotation. The file a reader holds open stops
// being the file at the path, and nothing says so: the check is the inode.

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
)

// Follower reads a log that is still being written. It holds the reader open
// between passes, so a quiet host costs a stat per poll rather than a re-read.
//
// Complete lines only: a record still being appended is held until its newline
// arrives, where scanAuditLog hands the last line over whether or not it ends.
//
// A Follower with no file is a state rather than a failure: the path holds none
// between logrotate's rename and the next record, and none at all on a host
// where nothing has been brokered yet. Detached, it reads nothing and reports
// no rotation until a file is there.
type Follower struct {
	path    string
	fh      *os.File
	reader  *bufio.Reader
	info    os.FileInfo
	pending []byte
	offset  int64
}

// OpenFollower is a follower on path, attached if there is a file there and
// detached if there is not.
func OpenFollower(path string) (*Follower, error) {
	f := &Follower{path: path}
	if err := f.open(); err != nil && !os.IsNotExist(err) {
		return nil, err
	}
	return f, nil
}

// open returns the raw error, not openAuditLog's sentence: the caller has to
// tell a path with no file at it, which is a pass to wait, from one that cannot
// be opened at all. Every field is cleared first, so a failure leaves a
// detached follower rather than one holding a closed reader.
func (f *Follower) open() error {
	f.fh, f.reader, f.info = nil, nil, nil
	f.pending, f.offset = nil, 0
	fh, err := os.Open(f.path)
	if err != nil {
		return err
	}
	info, err := fh.Stat()
	if err != nil {
		_ = fh.Close()
		return fmt.Errorf("%s: %w", f.path, err)
	}
	f.fh, f.info = fh, info
	f.reader = bufio.NewReaderSize(fh, 64*1024)
	return nil
}

// Following is whether there is a file open to read from.
func (f *Follower) Following() bool { return f.reader != nil }

// Reopen is the file the path names now, read from its start. The half-written
// line held from the file before is dropped with it: it belongs to a record in
// the rotated file.
func (f *Follower) Reopen() error {
	f.Close()
	return f.open()
}

func (f *Follower) Close() {
	if f.fh != nil {
		_ = f.fh.Close()
	}
}

// Drain calls visit with each line completed since the last pass, and returns
// when it reaches the end of what has been written. Blank lines are skipped,
// as in scanAuditLog. Nothing to read while detached, which is not an error:
// rotated() is what says a file has appeared.
func (f *Follower) Drain(visit func(line []byte)) error {
	if !f.Following() {
		return nil
	}
	for {
		chunk, err := f.reader.ReadBytes('\n')
		f.offset += int64(len(chunk))
		f.pending = append(f.pending, chunk...)
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", f.path, err)
		}
		line := f.pending
		f.pending = nil
		if len(bytes.TrimSpace(line)) > 0 {
			visit(line)
		}
	}
}

// Rotated is whether the file being read is no longer the log: logrotate
// renamed it and the path now names a different file, or something emptied it
// in place and it is shorter than what has already been read.
//
// A path with nothing at it is neither: that is the gap between logrotate's
// rename and the next record. A file at a path a detached follower holds
// counts, os.SameFile being false against its nil info, which is what attaches
// the follower to the first log a host ever writes.
func (f *Follower) Rotated() (bool, error) {
	info, err := os.Stat(f.path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, fmt.Errorf("%s: %w", f.path, err)
	}
	return !os.SameFile(info, f.info) || info.Size() < f.offset, nil
}
