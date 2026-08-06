// Package ptyutil opens a PTY pair without a third-party dependency.
//
// The three syscalls involved (open /dev/ptmx, TIOCSPTLCK to unlock, TIOCGPTN
// to name the slave) are what any pty library wraps, and doing them here keeps
// the process that handles secret output free of an extra dependency.
package ptyutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Open returns the master and slave ends of a new PTY pair.
func Open() (master, slave *os.File, err error) {
	m, err := os.OpenFile("/dev/ptmx", os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open /dev/ptmx: %w", err)
	}
	defer func() {
		if err != nil {
			_ = m.Close()
		}
	}()

	// Unlock the slave before naming it; the kernel refuses to open a locked one.
	if err = unix.IoctlSetPointerInt(int(m.Fd()), unix.TIOCSPTLCK, 0); err != nil {
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %w", err)
	}
	n, err := unix.IoctlGetInt(int(m.Fd()), unix.TIOCGPTN)
	if err != nil {
		return nil, nil, fmt.Errorf("TIOCGPTN: %w", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	s, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", name, err)
	}
	return m, s, nil
}

// SetWinsize sets the terminal dimensions on fd.  Failure is not fatal: a
// child that cannot learn the window size still runs.
func SetWinsize(fd uintptr, rows, cols int) {
	_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{
		Row: uint16(rows), Col: uint16(cols),
	})
}
