// Package fserr says what a filesystem error was, once.
//
// Go's own wrappers carry the call and the path: os.Stat returns "stat /nope:
// no such file or directory", and a caller that names the path again produces
// "editor /nope: stat /nope: no such file or directory". The reader wanted
// neither the second path nor the syscall.
package fserr

import (
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
)

// cause is the error under a wrapper that already carried the path: the errno
// on its own, in the words the C library uses for it.
func cause(err error) error {
	if pathErr, ok := errors.AsType[*os.PathError](err); ok {
		return pathErr.Err
	}
	if linkErr, ok := errors.AsType[*os.LinkError](err); ok {
		return linkErr.Err
	}
	if execErr, ok := errors.AsType[*exec.Error](err); ok {
		return execErr.Err
	}
	// A dial carries the address and the network as well: "dial unix /run/x.sock:
	// connect: no such file or directory" is four things around one.
	if opErr, ok := errors.AsType[*net.OpError](err); ok {
		return cause(opErr.Err)
	}
	if callErr, ok := errors.AsType[*os.SyscallError](err); ok {
		return callErr.Err
	}
	return err
}

// At is one sentence: the path, then what the kernel said about it. The cause
// is wrapped, so errors.Is still reaches the errno through it.
func At(path string, err error) error {
	return fmt.Errorf("%s: %w", path, cause(err))
}
