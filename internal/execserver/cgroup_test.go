package execserver

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// A pure-v2 host's /proc/<pid>/cgroup is one "0::" line; that path is where the
// run cgroups go.  A v1 or hybrid host has controller lines instead and no
// unified one, so confinement is off there rather than pointed at a controller
// cgroup it cannot use.
func TestUnifiedCgroupPathReadsOnlyTheV2Line(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"pure v2", "0::/system.slice/faramir-exec.service\n", "/system.slice/faramir-exec.service"},
		{"v2 among hybrid", "1:name=systemd:/x\n0::/system.slice/faramir-exec.service\n",
			"/system.slice/faramir-exec.service"},
		{"v1 only", "12:pids:/system.slice/x\n1:cpu:/y\n", ""},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := unifiedCgroupPath(tc.in); got != tc.want {
				t.Errorf("unifiedCgroupPath(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

// pids reads cgroup.procs, which is what drain watches to know a run's whole
// tree is gone -- the setsid child among it -- before the run is counted done.
func TestPidsReadsTheProcsFile(t *testing.T) {
	dir := t.TempDir()
	c := &runCgroup{path: dir}

	// No file yet: a cgroup already emptied and removed reads as no members, which
	// is what drain wants rather than an error.
	if got := c.pids(); len(got) != 0 {
		t.Errorf("pids of a cgroup with no procs file = %v, want none", got)
	}

	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("101\n2002\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	got := c.pids()
	if len(got) != 2 || got[0] != 101 || got[1] != 2002 {
		t.Errorf("pids = %v, want [101 2002]", got)
	}

	// Empty file: the members exited but the cgroup is not yet removed.
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	if got := c.pids(); len(got) != 0 {
		t.Errorf("pids of an empty procs file = %v, want none", got)
	}
}

// drain returns as soon as the set is empty, and reports failure rather than
// blocking for ever when something will not die -- the caller logs a uid that
// is not quiescent instead of hanging the run's teardown.
func TestDrainReturnsWhenEmptyAndBoundsItsWait(t *testing.T) {
	dir := t.TempDir()
	c := &runCgroup{path: dir}
	// No procs file at all reads as empty, so drain is immediate.
	if !c.drain(time.Second) {
		t.Error("drain of an empty cgroup did not return true")
	}

	// A member that stays put: drain gives up at the deadline rather than blocking.
	if err := os.WriteFile(filepath.Join(dir, "cgroup.procs"), []byte("1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	if c.drain(100 * time.Millisecond) {
		t.Error("drain reported empty while a member remained")
	}
	if waited := time.Since(start); waited < 100*time.Millisecond || waited > 2*time.Second {
		t.Errorf("drain waited %v, want about its 100ms bound", waited)
	}
}

// cgroupBase is "" unless a host both runs cgroup v2 and hands this process a
// delegated subtree it can write, so a host missing either refuses every run
// rather than reaping by the escapable process group.  Where a base is found it
// must be a real, writable cgroup directory, since a run is spawned into a child
// of it; where it is "" the discovery simply declined, which is a host to fix,
// not a state this test asserts.
func TestCgroupBaseIsARealDirectoryOrNothing(t *testing.T) {
	base := cgroupBase()
	if base == "" {
		return // no v2, or no delegated subtree: the executor would refuse to run here
	}
	if _, err := os.Stat(filepath.Join(base, "cgroup.procs")); err != nil {
		t.Errorf("cgroupBase returned %q, which is not a cgroup v2 directory: %v", base, err)
	}
}
