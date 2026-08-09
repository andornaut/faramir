// Package resolve turns the caller's cmd[0] into the absolute path the
// executor will run.
//
// This is all that is left of what used to be a default-deny allowlist.  The
// allowlist was removed because it never carried a security property: what
// keeps plaintext out of the agent's context is the uid split and the
// redactor, and a rule permitting any interpreter (bash, python, env) reached
// straight past every constraint it expressed.  It cost an operator a rule per
// program and cost the agent a denial per mistake, in exchange for tidiness.
//
// What remains is genuinely needed: the broker sends the executor an absolute
// path, so somebody has to work out which file a name refers to, and doing
// that wrong means running a *different* file.
//
// Two rules, both about agreeing with the child's own view of the world:
//
//   - A bare name is looked up on [exec.base_env] PATH, the PATH the child will
//     actually get, so a tool in a venv or a pipx install is reached by putting
//     it there.
//   - A relative path is resolved against the request's cwd, because that is
//     where the child runs.  Resolving it against the broker's own working
//     directory would silently execute a different file of the same name.
package resolve

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
)

// Error means cmd[0] does not name a program the broker can start.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// realpath resolves symlinks the way Python's os.path.realpath does: a
// component that does not exist is not an error, it is left in place.
func realpath(path string) string {
	if resolved, err := filepath.EvalSymlinks(path); err == nil {
		return resolved
	}
	return filepath.Clean(path)
}

// join mirrors Python's os.path.join: an absolute second argument wins
// outright, rather than being appended to the first.
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
func Program(argv0, cwd string, execCfg config.ExecConfig) (string, error) {
	if argv0 == "" {
		return "", errf("empty command")
	}

	if strings.Contains(argv0, "/") {
		resolved := realpath(join(cwd, argv0))
		// Existence, not executability.  The uid that execs this is the
		// executor's, which can hold permissions the broker does not, and
		// answering access(2) here would refuse a program that runs perfectly
		// well for the account that will run it.  The executor reports its own
		// failure; absence is refused here because it is the same answer from
		// any uid and is worth catching before a child is forked to find it.
		if !isFile(resolved) {
			return "", errf("%s: no such program (resolved to %s)", argv0, resolved)
		}
		return resolved, nil
	}

	// A bare name is a PATH search, and skipping what cannot be executed is what
	// a PATH search does: a non-executable file called "ls" in an early
	// directory is not the program the caller meant.  The bit is read as the
	// broker, which is the one uid available here and not the one that will run
	// it, so a program executable only by the executor reports as not found.
	// Both accounts are service accounts on the same host and program
	// directories are world-executable, so the two views differ only on a
	// deliberately narrowed one; an absolute path in cmd[0] is the way past it.
	path := execCfg.BaseEnv["PATH"]
	found := ""
	for dir := range strings.SplitSeq(path, ":") {
		candidate := filepath.Join(dir, argv0)
		if isFile(candidate) && executable(candidate) {
			found = candidate
			break
		}
	}
	if found == "" {
		return "", errf("%s: not found on the broker's PATH (%s). A program "+
			"installed elsewhere -- a venv, pipx, a version-manager shim -- "+
			"needs its directory on [exec.base_env] PATH, or an absolute "+
			"path in cmd[0].", argv0, path)
	}
	return realpath(found), nil
}
