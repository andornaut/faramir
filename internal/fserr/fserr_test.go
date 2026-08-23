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

// The three wrappers that carry a path, and anything else left as it is.
func TestCauseUnwrapsOnlyWhatCarriesThePath(t *testing.T) {
	inner := errors.New("the reason")
	for _, err := range []error{
		&os.PathError{Op: "stat", Path: "/x", Err: inner},
		&os.LinkError{Op: "rename", Old: "/x", New: "/y", Err: inner},
		&exec.Error{Name: "prog", Err: inner},
	} {
		if got := Cause(err); !errors.Is(got, inner) {
			t.Errorf("Cause(%T) = %v, want the errno under it", err, got)
		}
	}
	plain := errors.New("nothing wrapped")
	if got := Cause(plain); !errors.Is(got, plain) {
		t.Errorf("Cause left an unwrapped error as %v", got)
	}
	// And a wrapped one is still found through the wrapping.
	wrapped := os.NewSyscallError("x", inner)
	_ = wrapped
	if got := Cause(&os.PathError{Op: "open", Path: "/x", Err: os.ErrPermission}); !errors.Is(got, os.ErrPermission) {
		t.Errorf("Cause did not reach the errno: %v", got)
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
