// Package ptyutil opens a PTY pair without a third-party dependency: the three
// syscalls involved are what any pty library wraps.
package ptyutil

import (
	"fmt"
	"os"

	"golang.org/x/sys/unix"
)

// Every ioctl here goes through SyscallConn rather than File.Fd, and that is
// load-bearing rather than tidy. Fd takes the file out of the runtime's poller
// and returns it to blocking mode for good, and SetReadDeadline on a file in
// that state is accepted and then never fires: a read of a quiet child blocks
// until it writes something, whatever deadline the caller set. The caller
// reads the master with a deadline it depends on, so one Fd call anywhere on
// this file costs it every timeout it thought it had.

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
	if err = control(m, func(fd int) error {
		return unix.IoctlSetPointerInt(fd, unix.TIOCSPTLCK, 0)
	}); err != nil {
		return nil, nil, fmt.Errorf("TIOCSPTLCK: %w", err)
	}
	var n int
	if err = control(m, func(fd int) error {
		var ioctlErr error
		n, ioctlErr = unix.IoctlGetInt(fd, unix.TIOCGPTN)
		return ioctlErr
	}); err != nil {
		return nil, nil, fmt.Errorf("TIOCGPTN: %w", err)
	}
	name := fmt.Sprintf("/dev/pts/%d", n)
	s, err := os.OpenFile(name, os.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s: %w", name, err)
	}
	return m, s, nil
}

// SetWinsize sets the terminal dimensions. Failure is not fatal: this decides
// where a program folds its own output and nothing else.
func SetWinsize(f *os.File, rows, cols int) {
	_ = control(f, func(fd int) error {
		return unix.IoctlSetWinsize(fd, unix.TIOCSWINSZ, &unix.Winsize{
			Row: uint16(rows), Col: uint16(cols),
		})
	})
}

// control runs one ioctl on the file's descriptor, held open for the call.
func control(f *os.File, ioctl func(fd int) error) error {
	conn, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var ioctlErr error
	if err := conn.Control(func(fd uintptr) { ioctlErr = ioctl(int(fd)) }); err != nil {
		return err
	}
	return ioctlErr
}
