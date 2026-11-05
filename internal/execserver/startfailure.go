package execserver

// What a command that never started is answered with.

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"strconv"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/fserr"
)

// The codes a failed start is answered with. Named here as well as in the
// broker because this is where the difference is decided: the account that
// would have run the command is this one, so it is the one that can ask.
const (
	codeExecFailed    = "exec_failed"
	codeNotExecutable = "not_executable"
)

// startFailure names what went wrong, which is not always the program. The
// kernel refuses the exec when the working directory cannot be entered as well
// as when the binary cannot be run, and both arrive as one EACCES on the
// program's path.
//
// Asked here rather than by the broker because this runs as the account the
// answer is about. Only on a permission error, and only to add a sentence: what
// the exec reported is still what is returned.
//
// The advice to enrol the tree is for a command that runs in it as this
// account. A sudo the broker can have approved never gets it: the broker starts
// that one in / and passes the tree with -D, which root enters after the
// approval, or starts a login shell in / as sent.
func startFailure(program, cwd string, err error) (code, detail string) {
	// The path once and the errno on its own: exec wraps both in "fork/exec",
	// which names the call rather than the reason.
	detail = fserr.At(program, err).Error()
	// A file with the execute bit, no interpreter and no magic. Nothing about
	// the directory to weigh, and a shell answers it the same way it answers a
	// file it may not execute.
	if errors.Is(err, unix.ENOEXEC) {
		return codeNotExecutable, detail
	}
	if cwd == "" || !errors.Is(err, os.ErrPermission) {
		return codeExecFailed, detail
	}
	// Which of the two permissions was missing, said rather than left to the
	// caller: "permission denied" against a path they can read is about a uid
	// that is not theirs, and the cwd and the program are different fixes.
	//
	// Asked as execute rather than as a read, which is not the same permission:
	// entering a directory needs x and opening it needs r, so a 0710 home (what
	// sharing a tree leaves behind) would read as one this account cannot enter
	// while it walks through it, and blame the tree for a program that is not
	// executable.
	switch err := unix.Access(cwd, unix.X_OK); {
	case err == nil:
		// Named for the account, which is not the caller's: a brokered command
		// runs as this one.
		return codeNotExecutable, fmt.Sprintf("%s may not execute %s", whoRuns(), program)
	case !errors.Is(err, os.ErrPermission):
		// The directory answered something other than a refusal: a stale handle
		// or an I/O error on a mount that has gone. What the exec reported is
		// the answer, rather than a sentence about permissions on a tree whose
		// problem is the mount under it.
		return codeExecFailed, detail
	}
	// The program may be perfectly runnable; what failed is getting to where it
	// was to run. Not the shell's 126, which is about the program.
	return codeExecFailed, fmt.Sprintf("%s not started: %s cannot enter %s\n"+
		"  run `sudo faramir enrol` in the tree", program, whoRuns(), cwd)
}

// whoRuns names the account a brokered command runs as, which is this process's
// own, falling back to the uid where the name cannot be read.
func whoRuns() string {
	who := strconv.Itoa(os.Getuid())
	if u, err := user.LookupId(who); err == nil {
		who = u.Username
	}
	return who
}
