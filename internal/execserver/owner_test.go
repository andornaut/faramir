package execserver

import (
	"os/exec"
	"syscall"
	"testing"
)

// ownerOf is the half of the escalation this daemon answers: which run forked the
// process asking to sudo. Everything it is given is the caller's claim, so these
// are mostly about what it refuses.
//
// Real processes and real pidfds, because what is being tested is that the fd
// answers for the process rather than for the number.

// forked starts a live child the way run() does, and returns its pid and the
// pidfd the fork produced. The caller owns the fd unless it hands it to own().
func forked(t *testing.T) (*exec.Cmd, int, int) {
	t.Helper()
	pidfd := -1
	cmd := exec.CommandContext(t.Context(), "/bin/sleep", "30")
	cmd.SysProcAttr = &syscall.SysProcAttr{PidFD: &pidfd}
	if err := cmd.Start(); err != nil {
		t.Fatalf("could not start a child to be owned: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	if pidfd < 0 {
		t.Skip("this kernel returned no pidfd; the check under test cannot run here")
	}
	return cmd, cmd.Process.Pid, pidfd
}

// ownerExecutor is this file's bookkeeping on its own: the socket, cgroups and
// slots of a real one are not what ownership is about.
func ownerExecutor() *Executor { return &Executor{owned: map[string]ownedRun{}} }

func TestOwnerOfNamesTheRunThatForkedTheProcess(t *testing.T) {
	e := ownerExecutor()
	_, pid, fd := forked(t)
	e.own("run-a", pid, fd)

	// The ancestry the helper walked: the sudo, a shell, then what was forked.
	if runID := e.ownerOf([]int{999999, 999998, pid})["run_id"]; runID != "run-a" {
		t.Errorf("run_id = %v, want run-a", runID)
	}
}

// The process this run was forked as has been reaped, so the kernel is free to
// hand its number to something else. The pidfd is what notices: the number alone
// would still match, and would attribute an escalation to whatever now holds it.
func TestOwnerOfRefusesAReapedProcess(t *testing.T) {
	e := ownerExecutor()
	cmd, pid, fd := forked(t)
	e.own("run-a", pid, fd)

	if runID := e.ownerOf([]int{pid})["run_id"]; runID != "run-a" {
		t.Fatalf("run_id = %v before the reap, want run-a", runID)
	}
	if err := cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	// The reap: until this the number is still the child's, zombie or not.
	_ = cmd.Wait()

	if runID := e.ownerOf([]int{pid})["run_id"]; runID != "" {
		t.Errorf("run_id = %v; a pid the kernel may have handed on was still "+
			"attributed to a run", runID)
	}
}

func TestOwnerOfRefusesWhatNoRunForked(t *testing.T) {
	e := ownerExecutor()
	_, pid, fd := forked(t)
	e.own("run-a", pid, fd)

	for name, ancestors := range map[string][]int{
		"nothing named":     {},
		"none of them ours": {999999, 999998},
	} {
		t.Run(name, func(t *testing.T) {
			answer := e.ownerOf(ancestors)
			if runID := answer["run_id"]; runID != "" {
				t.Errorf("run_id = %v, want none", runID)
			}
			if detail, said := answer["detail"].(string); !said || detail == "" {
				t.Error("the answer carries no reason, so a refusal cannot be diagnosed")
			}
		})
	}
}

// A run stops being answerable the moment it is disowned, which the reap is what
// triggers: an approval must not outlive the command it was given for.
func TestDisownEndsTheRun(t *testing.T) {
	e := ownerExecutor()
	_, pid, fd := forked(t)
	e.own("run-a", pid, fd)

	e.disown("run-a")
	if runID := e.ownerOf([]int{pid})["run_id"]; runID != "" {
		t.Errorf("run_id = %v after the run was disowned", runID)
	}
	// Idempotent: the reap and the run's own teardown both call it, and a double
	// close would take an fd another run had been given by then.
	e.disown("run-a")
}

// Two ways a run ends up unattributable, both of which must leave it unable to
// escalate rather than able to.
func TestARunWithNothingToCheckIsNotOwned(t *testing.T) {
	for name, args := range map[string]struct {
		runID string
		pidfd int
	}{
		// A host that grants no escalation: the broker names no run.
		"no run id": {runID: "", pidfd: -1},
		// A kernel without CLONE_PIDFD, where nothing could tell the process from
		// one that reused its number.
		"no pidfd": {runID: "run-a", pidfd: -1},
	} {
		t.Run(name, func(t *testing.T) {
			e := ownerExecutor()
			e.own(args.runID, 4242, args.pidfd)
			if len(e.owned) != 0 {
				t.Errorf("owned = %v, want empty", e.owned)
			}
			if runID := e.ownerOf([]int{4242})["run_id"]; runID != "" {
				t.Errorf("run_id = %v, want none", runID)
			}
		})
	}
}
