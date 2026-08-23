// Package resolve turns the caller's cmd[0] into the absolute path the executor
// will run. There is no allowlist: what keeps plaintext out of the agent's
// context is the uid split and the redactor.
//
// Two rules, both about agreeing with the child's view of the world:
//
//   - A bare name is looked up on [command.env] PATH, the PATH the child gets.
//   - A relative path is resolved against the request's cwd, where the child
//     runs; the broker's own directory could hold a different file of the same
//     name.
package resolve

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

// Program returns the absolute, symlink-resolved path for argv0.
func Program(argv0, cwd string, execCfg config.CommandConfig) (string, error) {
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
				return "", fmt.Errorf("%s: not a program: %s is a %s", argv0, resolved,
					describeKind(there.Mode()))
			}
			// Where resolving changed nothing, saying so names the same path twice.
			if resolved == argv0 {
				return "", fmt.Errorf("%s: no such program", argv0)
			}
			return "", fmt.Errorf("%s: no such program (resolved to %s)", argv0, resolved)
		}
		return resolved, nil
	}

	// A PATH search skips what cannot be executed. The bit is read as the broker
	// rather than the uid that will run it, so a program executable only by the
	// executor reports as not found; an absolute path in cmd[0] is the way past
	// that.
	path := execCfg.Env["PATH"]
	found := ""
	for dir := range strings.SplitSeq(path, ":") {
		// An empty or relative component means the working directory to a shell,
		// and the broker's is not the child's. Skipped rather than resolved against
		// the request's cwd, a PATH the operator writes being no place to name a
		// directory the agent chooses.
		if !filepath.IsAbs(dir) {
			continue
		}
		candidate := filepath.Join(dir, argv0)
		if isFile(candidate) && executable(candidate) {
			found = candidate
			break
		}
	}
	if found == "" {
		return "", fmt.Errorf("%s: not found on the broker's PATH (%s). A program "+
			"installed elsewhere -- a venv, pipx, a version-manager shim -- "+
			"needs its directory on [command.env] PATH, or an absolute "+
			"path in cmd[0]", argv0, path)
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
