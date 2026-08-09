// Package ptyutil opens a PTY pair without a third-party dependency: the three
// syscalls involved are what any pty library wraps.
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

	// Unlock before naming: the kernel refuses to open a locked slave.
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

// SetWinsize sets the terminal dimensions on fd.  Failure is not fatal.
func SetWinsize(fd uintptr, rows, cols int) {
	_ = unix.IoctlSetWinsize(int(fd), unix.TIOCSWINSZ, &unix.Winsize{
		Row: uint16(rows), Col: uint16(cols),
	})
}
