package execserver

import (
	"crypto/rand"
	"encoding/hex"
	"log"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Per-run cgroup confinement: a brokered command is spawned into a cgroup of its
// own and the whole cgroup is torn down when the run ends.  This is the one
// reaper, with no process-group fallback.  A process group (what Setsid sets up
// and killpg reaches) is escaped by a child that calls setsid(), which starts a
// new session and group the signal misses, while a cgroup is not escapable: a
// descendant inherits it and cannot move out without write on another cgroup,
// which this uid does not have, so cgroup.kill reaps the whole tree, the setsid
// child among it, atomically.
//
// It needs cgroup v2, a unit granted Delegate=, and cgroup.kill (kernel >= 5.14).
// `init` renders Delegate= on the executor unit for every install, approval or
// not, so a real host always confines.  A host that cannot (an old kernel, a
// container without delegation) refuses every command rather than reaping by
// process group, because a silent degrade there is the failure this closes: an
// approval's serialization rests on a run leaving no straggler that could sit
// through the next approval window, and even without approval an unreaped setsid
// child is a process outliving the run that spawned it.
//
// `faramir doctor` fails a host whose executor unit lost the delegation.

// cgroupBase is the cgroup v2 directory this executor may create run cgroups
// under, or "" when confinement is unavailable.  Probed once at startup: per run
// it is a field read, not a syscall.
func cgroupBase() string {
	rel, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}
	unified := unifiedCgroupPath(string(rel))
	if unified == "" {
		return "" // no v2 membership line: a cgroup v1 host, or none at all
	}
	// Every visible cgroup2 mount is tried, not just the first: the membership path
	// is relative to whichever mount this process's hierarchy is reached through,
	// and joining it to an unrelated one names a directory that does not exist.
	// The probe below is what settles it, so the mount that answers is the mount
	// that gets used.
	for _, mount := range cgroup2Mounts() {
		if base := filepath.Join(mount, unified); usableCgroup(base) {
			return base
		}
	}
	return ""
}

// usableCgroup reports whether run cgroups can be made under this directory.
// Two gates in one probe: a sub-cgroup is created and removed.  The mkdir
// succeeds only where the unit was granted Delegate=: without it systemd owns
// this directory and the uid cannot write here, which is the real delegation
// check, a mode being able to lie about who may write.  Its cgroup.kill file
// exists only on a kernel >= 5.14, which is the feature this reaps a tree with.
// Either missing means the host cannot confine, and the executor will refuse to
// run rather than run unreaped.
func usableCgroup(base string) bool {
	probe := filepath.Join(base, "faramir-cgroup-probe")
	if err := os.Mkdir(probe, 0o755); err != nil {
		return false
	}
	_, killErr := os.Stat(filepath.Join(probe, "cgroup.kill"))
	_ = os.Remove(probe)
	return killErr == nil
}

// CanConfine reports whether this executor found a delegated cgroup at startup.
// It is false where every command would be refused, which is a host to fix.
func (e *Executor) CanConfine() bool { return e.cgroupBase != "" }

// cgroup2Mounts is where the unified hierarchy is mounted, in the order
// /proc/self/mounts lists it.  It is /sys/fs/cgroup on a pure-v2 host and a
// subdirectory of it on a hybrid one, so the location is looked up rather than
// assumed, and a namespace can show more than one.  Read the per-process file,
// never /proc/mounts: the executor unit sets ProcSubset=pid, which mounts procfs
// with subset=pid and hides every non-pid top-level entry, /proc/mounts among
// them, while /proc/self/mounts stays readable.
func cgroup2Mounts() []string {
	data, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return nil
	}
	return cgroup2MountsIn(string(data))
}

// cgroup2MountsIn is the parse, split out so it can be tested against a mount
// table this host does not have.
func cgroup2MountsIn(mounts string) []string {
	var out []string
	for _, line := range strings.Split(mounts, "\n") {
		if fields := strings.Fields(line); len(fields) >= 3 && fields[2] == "cgroup2" {
			out = append(out, fields[1])
		}
	}
	return out
}

// unifiedCgroupPath is the path from the "0::" line of /proc/<pid>/cgroup, the
// process's cgroup v2 membership relative to the unified mount, or "".  Every
// host that mounts v2 at all has this line (it is "/" for a process in the root
// of the hierarchy); a pure cgroup v1 host has only controller lines and none.
func unifiedCgroupPath(procCgroup string) string {
	for _, line := range strings.Split(procCgroup, "\n") {
		if after, ok := strings.CutPrefix(line, "0::"); ok {
			return after
		}
	}
	return ""
}

// runCgroup is one run's cgroup.  The child is spawned directly into it via
// clone3's CLONE_INTO_CGROUP (SysProcAttr.UseCgroupFD), so the confinement holds
// from the first instruction and there is no window in which a descendant runs
// outside it.
type runCgroup struct {
	path string
	fd   int
}

// newRunCgroup makes a fresh cgroup and opens the directory fd the spawn needs.
// The id is random rather than the pid, which is not known until after the fork
// this fd is for.
func newRunCgroup(base string) (*runCgroup, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return nil, err
	}
	path := filepath.Join(base, "run-"+hex.EncodeToString(raw[:]))
	if err := os.Mkdir(path, 0o755); err != nil {
		return nil, err
	}
	fd, err := syscall.Open(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		_ = os.Remove(path)
		return nil, err
	}
	return &runCgroup{path: path, fd: fd}, nil
}

// kill removes every process in the cgroup atomically, a setsid descendant
// included.  cgroup.kill is guaranteed here: cgroupBase refused a host without
// it, so the executor never reaches this on a kernel that lacks it.
func (c *runCgroup) kill() {
	if err := os.WriteFile(filepath.Join(c.path, "cgroup.kill"), []byte("1"), 0); err != nil {
		log.Printf("cgroup %s: cgroup.kill failed (%v); tree may not be reaped",
			filepath.Base(c.path), err)
	}
}

// terminate ends the run's tree gracefully: a SIGTERM to every member first,
// then cgroup.kill for whatever is left once the grace runs out.  Both phases
// address the cgroup, so a setsid child that left the process group is reached
// the same as the rest.  There is no separate process-group signal; this is the
// one mechanism.
func (c *runCgroup) terminate(graceSec int) {
	for _, pid := range c.pids() {
		_ = syscall.Kill(pid, syscall.SIGTERM)
	}
	if c.drain(time.Duration(graceSec) * time.Second) {
		return
	}
	c.kill()
	if !c.drain(5 * time.Second) {
		log.Printf("cgroup %s: %d process(es) survived SIGKILL",
			filepath.Base(c.path), len(c.pids()))
	}
}

// pids reads the cgroup's current members.
func (c *runCgroup) pids() []int {
	data, err := os.ReadFile(filepath.Join(c.path, "cgroup.procs"))
	if err != nil {
		return nil
	}
	var out []int
	for _, field := range strings.Fields(string(data)) {
		if pid, err := strconv.Atoi(field); err == nil {
			out = append(out, pid)
		}
	}
	return out
}

// drain waits until the cgroup is empty, so "the run ended" means no process of
// it is left to sit through the next approval window.  Bounded: a member that
// will not die is left for close to report rather than waited on for ever.
func (c *runCgroup) drain(timeout time.Duration) bool {
	deadline := time.Now().Add(timeout)
	for {
		if len(c.pids()) == 0 {
			return true
		}
		if !time.Now().Before(deadline) {
			return false
		}
		time.Sleep(20 * time.Millisecond)
	}
}

// close kills whatever is left, waits for the cgroup to empty, and removes it.
// Run on every exit, a normal one included: the child may have returned zero
// while a setsid grandchild lives on, and reaping that is what this exists for.
func (c *runCgroup) close() {
	_ = syscall.Close(c.fd)
	c.kill()
	if !c.drain(5 * time.Second) {
		// A run whose descendants would not die: reported so an operator sees it, and
		// on a host that allows sudo it is the quiescence the serialization needs.
		log.Printf("cgroup %s still holds %d process(es) after kill",
			filepath.Base(c.path), len(c.pids()))
	}
	_ = os.Remove(c.path) // rmdir, which succeeds once the set is empty
}
