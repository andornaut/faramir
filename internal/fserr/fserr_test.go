package fserr

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The wrapper Go returns carries the call and the path, so a caller that names
// the path again says it twice and names a syscall nobody asked about.
func TestAtNamesThePathOnceAndNoSyscall(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "nope")
	_, err := os.Stat(missing)
	if err == nil {
		t.Fatal("a path that is not there did not fail")
	}
	got := At(missing, err).Error()
	if strings.Count(got, missing) != 1 {
		t.Errorf("the path appears %d times: %s", strings.Count(got, missing), got)
	}
	for _, unwanted := range []string{"stat ", "lstat ", "open "} {
		if strings.Contains(got, unwanted) {
			t.Errorf("the message names the call (%q): %s", unwanted, got)
		}
	}
	if !strings.Contains(got, "no such file or directory") {
		t.Errorf("the message drops what the kernel said: %s", got)
	}
}

// Every wrapper that carries a path, and anything else left as it is.
//
// The errno itself rather than something that unwraps to it: every wrapper here
// has an Unwrap, so errors.Is reaches the errno through one that was never
// taken off, and an assertion written that way holds whether cause unwrapped or
// returned its argument.
func TestCauseUnwrapsOnlyWhatCarriesThePath(t *testing.T) {
	inner := errors.New("the reason")
	for _, tc := range []struct {
		name string
		err  error
	}{
		{"a path error", &os.PathError{Op: "stat", Path: "/x", Err: inner}},
		{"a link error", &os.LinkError{Op: "rename", Old: "/x", New: "/y", Err: inner}},
		{"a program that would not start", &exec.Error{Name: "prog", Err: inner}},
		{"a syscall error", os.NewSyscallError("connect", inner)},
		{"a dial, which carries the address as well", &net.OpError{
			Op: "dial", Net: "unix", Err: os.NewSyscallError("connect", inner)}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			//nolint:errorlint // identity is the assertion: errors.Is reaches the
			// errno through a wrapper cause left on, so it cannot fail here.
			if got := cause(tc.err); got != inner {
				t.Errorf("cause(%T) = %v (%T), want the errno under it", tc.err, got, got)
			}
		})
	}
	plain := errors.New("nothing wrapped")
	//nolint:errorlint // identity again, for the error that carries no path
	if got := cause(plain); got != plain {
		t.Errorf("cause left an unwrapped error as %v", got)
	}
}

// A dial carries the network and the address as well as the errno, so a caller
// that names the socket produces "/run/x.sock: dial unix /run/x.sock: connect:
// no such file or directory": the path twice and two layers of plumbing.
func TestADialSaysOnlyWhatWentWrong(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "absent.sock")
	_, err := net.Dial("unix", sock)
	if err == nil {
		t.Fatal("dialling a socket that is not there did not fail")
	}
	got := At(sock, err).Error()
	if strings.Count(got, sock) != 1 {
		t.Errorf("the path appears %d times: %s", strings.Count(got, sock), got)
	}
	for _, unwanted := range []string{"dial ", "connect:"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("the message carries %q: %s", unwanted, got)
		}
	}
	if !strings.Contains(got, "no such file or directory") {
		t.Errorf("the message drops what the kernel said: %s", got)
	}
}
