package execserver

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// A process of this uid that belongs to no run is what an approval must not be
// granted alongside: it can read the approved run's token out of /proc, exec
// with it set, and sudo on it.  So it is reported, by pid, and the answer is
// not quiet.
func TestQuiescenceSeesAProcessOutsideEveryRun(t *testing.T) {
	e := &Executor{live: map[*runCgroup]struct{}{}}
	stray := sleeper(t)

	if quiet, _ := e.quiescence()["quiescent"].(bool); quiet {
		t.Fatal("a process of this uid outside every run was reported as quiet")
	}
	// Against the whole list rather than the message, which names only the first
	// few: this test runs on a host with other processes of its uid, and a real
	// executor's uid runs nothing but its runs.
	found, err := e.strays()
	if err != nil {
		t.Fatal(err)
	}
	if !names(found, stray) {
		t.Errorf("strays = %v, want the unaccounted-for pid %d named: an operator "+
			"has to be able to find what is holding the approval off", found, stray)
	}
	// The daemon asking the question is not one of them.  Left in, every host
	// would be permanently un-quiet and no approval would ever take.
	if names(found, os.Getpid()) {
		t.Errorf("strays = %v, want this process left out of its own count", found)
	}
}

// names reports whether the list holds an entry for this pid.  The entries read
// "<pid> (<comm>)", so the pid is matched whole rather than as a substring of a
// longer number.
func names(strays []string, pid int) bool {
	for _, stray := range strays {
		if strings.HasPrefix(stray, strconv.Itoa(pid)+" (") {
			return true
		}
	}
	return false
}

// A member of a run this executor is confining is accounted for: it is the
// approved command, or one of its descendants, which is what the approval is
// for.  Tracked through the run's cgroup, so a run still tearing down still
// counts: until the cgroup is empty there is no telling the approved run's
// processes from a straggler.
func TestQuiescenceAccountsForAConfinedRun(t *testing.T) {
	e := &Executor{live: map[*runCgroup]struct{}{}}
	member := sleeper(t)

	// A cgroup directory with the member in it.  The real one is made by the
	// kernel; what is read from it is this file, and this test is about the
	// accounting rather than the confinement.
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"),
		[]byte(strconv.Itoa(member)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	e.track(&runCgroup{path: dir, fd: -1})

	found, err := e.strays()
	if err != nil {
		t.Fatal(err)
	}
	if names(found, member) {
		t.Errorf("strays = %v, want the member of a confined run left out: it is "+
			"the command being approved", found)
	}
}

// sleeper starts a child of this uid and returns its pid, reaped by the test.
func sleeper(t *testing.T) int {
	t.Helper()
	cmd := exec.Command("sleep", "60")
	if err := cmd.Start(); err != nil {
		t.Skipf("this host cannot start a child to stand in for a stray: %v", err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	return cmd.Process.Pid
}
