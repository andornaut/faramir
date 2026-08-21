package execserver

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// Which run forked a process, answered for the broker. Only this service knows:
// it did the fork.
//
// A pid alone would not do. The kernel hands the number to something else once
// the process is reaped, so an entry that outlived its child would attribute an
// escalation to whatever got the number next. The start time that would settle
// it cannot be read here: a brokered command that execs a setuid binary -- sudo
// itself, which is the case that matters -- gets a root-owned /proc entry, and
// ProtectProc=invisible hides it from the uid this service runs as.
//
// So the fork itself is asked for the answer. clone3 returns a pidfd, which
// refers to the process rather than to the number, and it is taken before the
// exec that hides /proc. Signal 0 through it says whether that process is still
// alive: alive means the number is still its own, because a pid is not reused
// until the process holding it is reaped. A number reused by anything else fails
// the check rather than passing it.
type ownedRun struct {
	pid int
	// pidfd is this service's handle on the process it forked, closed with the
	// run. -1 is a kernel without CLONE_PIDFD, which is not a host faramir
	// supports: the run is left unowned, so nothing inside it can escalate.
	pidfd int
}

// own records what a run was forked as. It takes ownership of pidfd, closing it
// on every path that does not store it.
//
// A run the broker gave no id is a host that grants no escalation: nothing to
// attribute, and nothing that could ask.
func (e *Executor) own(runID string, pid, pidfd int) {
	if runID == "" || pidfd < 0 {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		if runID != "" {
			log.Printf("this kernel gave no pidfd for pid %d, so nothing in that run "+
				"can be told from a process that reused its number; it will not be able "+
				"to sudo", pid)
		}
		return
	}
	e.ownedMu.Lock()
	defer e.ownedMu.Unlock()
	e.owned[runID] = ownedRun{pid: pid, pidfd: pidfd}
}

// disown drops a run the moment its child is reaped, which is when the kernel is
// free to hand the number on. Idempotent: the reap and the run's own teardown
// both call it.
func (e *Executor) disown(runID string) {
	if runID == "" {
		return
	}
	e.ownedMu.Lock()
	defer e.ownedMu.Unlock()
	if owned, held := e.owned[runID]; held {
		_ = unix.Close(owned.pidfd)
		delete(e.owned, runID)
	}
}

// stillRunning reports whether the process this pidfd refers to is still there. Signal
// 0 is delivered to nothing and only asks the question. Every failure is a no:
// the answer decides whether root is handed out.
func stillRunning(pidfd int) bool {
	return unix.PidfdSendSignal(pidfd, 0, nil, 0) == nil
}

// ownerOf names the run that forked one of these processes, or none.
//
// The ancestry is the caller's, and every entry in it is a claim rather than a
// fact. What makes the answer worth anything is that it is checked twice against
// what this service holds: the pid against what it forked, and the pidfd against
// whether that process is still the one wearing the number.
func (e *Executor) ownerOf(ancestors []int) map[string]any {
	if len(ancestors) == 0 {
		return map[string]any{"run_id": "", "detail": "the request named no processes"}
	}
	e.ownedMu.Lock()
	defer e.ownedMu.Unlock()
	for _, pid := range ancestors {
		for runID, owned := range e.owned {
			if owned.pid != pid {
				continue
			}
			if !stillRunning(owned.pidfd) {
				// The process this run was forked as has been reaped, so the number is
				// no longer proof of anything. Blocked rather than matched.
				log.Printf("pid %d was %s's command and has been reaped; the process "+
					"asking is not it", pid, runID)
				continue
			}
			return map[string]any{"run_id": runID, "detail": fmt.Sprintf(
				"pid %d is the command this run was forked as, and is still running", pid)}
		}
	}
	return map[string]any{"run_id": "", "detail": fmt.Sprintf(
		"none of the %d process(es) named is a brokered command this executor "+
			"forked and still has in flight", len(ancestors))}
}

// Owner asks the executor which of its runs forked one of these processes. The
// broker calls it when an escalation is raised; see Executor.ownerOf for why the
// broker cannot answer it. Every failure is "none": an executor that cannot be
// reached has not attributed anything, and an escalation nobody can attribute is
// the thing this refuses.
func Owner(socketPath string, ancestors []int, timeout time.Duration) (runID, detail string) {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return "", fmt.Sprintf("the executor could not be asked what it forked "+
			"(%s: %v)", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := sockutil.Send(conn, request{
		Op: opOwner, Version: version.Version, Procs: ancestors,
	}); err != nil {
		return "", fmt.Sprintf("the executor could not be asked what it forked (%v)", err)
	}
	line, err := sockutil.ReadLine(conn, maxRequestBytes)
	if err != nil || len(line) == 0 {
		return "", fmt.Sprintf("the executor did not say what it forked (%v)", err)
	}
	var response struct {
		RunID  string `json:"run_id"`
		Detail string `json:"detail"`
		Error  *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return "", "the executor's answer about what it forked was malformed"
	}
	if response.Error != nil {
		return "", response.Error.Message
	}
	if response.Detail == "" {
		response.Detail = "the executor gave no reason"
	}
	return response.RunID, response.Detail
}
