package broker

// Turning the caller's cmd[0] into the absolute path the executor will run.
// There is no allowlist: what keeps plaintext out of the agent's context is the
// uid split and the redactor.
//
// Two rules, both about agreeing with the child's view of the world:
//
//   - A bare name is looked up on [command.env] PATH, the PATH the child gets.
//   - A relative path is resolved against the request's cwd, where the child
//     runs; the broker's own directory could hold a different file of the same
//     name.

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
)

// realpath resolves symlinks, leaving a component that does not exist in
// place.
func realpath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

// join lets an absolute second argument win outright.
func join(cwd, path string) string {
	if filepath.IsAbs(path) {
		return path
	}
	return filepath.Join(cwd, path)
}

func isFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func executable(path string) bool { return unix.Access(path, unix.X_OK) == nil }

// executableByNobody reports whether a file carries no execute bit at all.
// Asked of the mode rather than with Access, which answers for this process:
// the executor's uid is not the broker's, and a program only the executor can
// run is one the broker must not call unrunnable.
func executableByNobody(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().Perm()&0o111 == 0
}

// The two ways a program can fail to be one, told apart because a caller
// branches on them: the shell answers a program it could not find with 127 and
// one it found and could not run with 126, and `faramir run` gives the same
// numbers. Every other failure is the command not running for a reason the
// caller has to read rather than test.
var (
	// errNotFound is nothing at the named path, or nothing on the PATH.
	errNotFound = errors.New("no such program")
	// errNotExecutable is a path that is there and is not something the kernel
	// can run: a directory, a device, a socket.
	errNotExecutable = errors.New("not executable")
)

// kindError carries one of those alongside a message written for a reader. The
// message is the whole of what is shown, so naming the kind costs it nothing:
// wrapping with %w would append a second sentence saying what the first
// already says.
type kindError struct {
	kind error
	text string
}

func (e kindError) Error() string { return e.text }
func (e kindError) Unwrap() error { return e.kind }

// notFoundf and notExecutablef are fmt.Errorf for those two kinds.
func notFoundf(format string, a ...any) error {
	return kindError{kind: errNotFound, text: fmt.Sprintf(format, a...)}
}

func notExecutablef(format string, a ...any) error {
	return kindError{kind: errNotExecutable, text: fmt.Sprintf(format, a...)}
}

// resolveProgram returns the absolute, symlink-resolved path for argv0.
func resolveProgram(argv0, cwd string, execCfg config.CommandConfig) (string, error) {
	if argv0 == "" {
		return "", errors.New("empty command")
	}

	if strings.Contains(argv0, "/") {
		resolved := realpath(join(cwd, argv0))
		// Existence, not executability: the executor's uid can hold permissions the
		// broker does not. Absence is the same answer from any uid.
		//
		// A directory, a device or a socket fails the same test and is not the same
		// thing to be told about: "no such program" about a path the caller can see
		// reads as a typo in the path rather than as a path that is not a program.
		if !isFile(resolved) {
			if there, err := os.Stat(resolved); err == nil {
				return "", notExecutablef("%s: not a program: %s is a %s", argv0, resolved,
					describeKind(there.Mode()))
			}
			// Where resolving changed nothing, saying so names the same path twice.
			if resolved == argv0 {
				return "", notFoundf("%s: no such program", argv0)
			}
			return "", notFoundf("%s: no such program (resolved to %s)", argv0, resolved)
		}
		return resolved, nil
	}

	// A PATH search skips what cannot be executed. The bit is read as the broker
	// rather than the uid that will run it, so a program executable only by the
	// executor reports as not found; an absolute path in cmd[0] is the way past
	// that.
	path := execCfg.Env["PATH"]
	found, unrunnable := "", ""
	for dir := range strings.SplitSeq(path, ":") {
		// An empty or relative component means the working directory to a shell,
		// and the broker's is not the child's. Skipped rather than resolved against
		// the request's cwd, a PATH the operator writes being no place to name a
		// directory the agent chooses.
		if !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, argv0)
		if !isFile(candidate) {
			continue
		}
		if executable(candidate) {
			found = candidate
			break
		}
		// There and executable by nobody, which is not the same as one this uid
		// may not run: a program only the executor can execute is reported below
		// as not found, and an absolute path is the way past that. Told apart
		// because the answers differ -- install it, or chmod it -- and "not
		// found on the PATH" about a file sitting on the PATH sends an operator
		// to install what is already there.
		if unrunnable == "" && executableByNobody(candidate) {
			unrunnable = candidate
		}
	}
	if found == "" && unrunnable != "" {
		return "", notExecutablef("%s: %s is not executable by any account",
			argv0, unrunnable)
	}
	if found == "" {
		return "", notFoundf("%s: not found on the broker's PATH (%s). For a "+
			"program installed elsewhere (a venv, pipx, a version-manager shim), "+
			"add its directory to [command.env] PATH or use an absolute path "+
			"in cmd[0]", argv0, path)
	}
	return realpath(found), nil
}

// describeKind names what is at a path that is not a regular file, in the words
// somebody would use for it.
func describeKind(mode os.FileMode) string {
	switch {
	case mode.IsDir():
		return "directory"
	case mode&os.ModeDevice != 0 && mode&os.ModeCharDevice != 0:
		return "character device"
	case mode&os.ModeDevice != 0:
		return "block device"
	case mode&os.ModeSocket != 0:
		return "socket"
	case mode&os.ModeNamedPipe != 0:
		return "named pipe"
	}
	return "not a regular file"
}
