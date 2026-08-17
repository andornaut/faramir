package execserver

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Per-run cgroup confinement: a brokered command is spawned into a cgroup of its
// own and the whole cgroup is torn down when the run ends.  A descendant
// inherits the cgroup and cannot move out without write on another one, which
// this uid does not have, so cgroup.kill reaps the whole tree atomically,
// including a child that called setsid() and left the process group behind.
//
// This is the one reaper, with no process-group fallback: a host that cannot
// confine refuses every command rather than degrading to the escapable
// mechanism.  See docs/design.md for why there is no fallback.  It needs cgroup
// v2, a unit granted Delegate=, and cgroup.kill (kernel >= 5.14).
//
// The unit's own cgroup is the outer one, which is why nothing sweeps run
// cgroups at startup.  Run cgroups are made under this executor's own delegated
// subtree, and faramir-exec.service takes systemd's default
// KillMode=control-group: a dead executor, SIGKILLed included, has that whole
// subtree stopped and removed before the restart, and a member cannot move out
// of it.  So a run cgroup never outlives the process that made it, and a startup
// sweep would find nothing.  A unit edited to KillMode=process or mixed breaks
// that; the strays an approval is then refused on are the symptom.

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
	probe, err := probePath(base)
	if err != nil {
		return false
	}
	if err := os.Mkdir(probe, 0o755); err != nil {
		return false
	}
	_, killErr := os.Stat(filepath.Join(probe, "cgroup.kill"))
	_ = os.Remove(probe)
	return killErr == nil
}

// probePath names one probe, and names it differently every time.  A fixed name
// is left behind by anything that stops this process between the mkdir above and
// the remove after it, and by a second instance probing at the same moment; the
// next mkdir then fails with EEXIST, which reads here as a host that cannot
// confine.  That refuses every brokered command, and says the host needs cgroup
// v2, a delegated unit and a 5.14 kernel, none of which is what is wrong.
func probePath(base string) (string, error) {
	var raw [8]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return filepath.Join(base, "faramir-probe-"+hex.EncodeToString(raw[:])), nil
}

// CanConfine reports whether this executor found a delegated cgroup at startup.
// It is false where every command would be refused, which is a host to fix.
func (e *Executor) CanConfine() bool { return e.cgroupBase != "" }

// cgroup2Mounts is where the unified hierarchy is mounted, in the order
// /proc/self/mounts lists it.  It is /sys/fs/cgroup on a pure-v2 host and a
// subdirectory of it on a hybrid one, so the location is looked up rather than
// assumed, and a namespace can show more than one.  Read the per-process file,
// never /proc/mounts: a unit setting ProcSubset=pid mounts procfs with subset=pid
// and hides every non-pid top-level entry, /proc/mounts among them, while
// /proc/self/mounts stays readable.
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
	for line := range strings.SplitSeq(mounts, "\n") {
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
	for line := range strings.SplitSeq(procCgroup, "\n") {
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
	for field := range strings.FieldsSeq(string(data)) {
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

// --------------------------------------------------------------------------
// Quiescence
// --------------------------------------------------------------------------

// track and untrack keep the set of run cgroups the quiescence answer measures
// against.
func (e *Executor) track(c *runCgroup) {
	e.liveMu.Lock()
	defer e.liveMu.Unlock()
	e.live[c] = struct{}{}
}

func (e *Executor) untrack(c *runCgroup) {
	e.liveMu.Lock()
	defer e.liveMu.Unlock()
	delete(e.live, c)
}

// quiescence reports whether any process of this uid is alive outside this
// daemon and outside the runs it is confining.
//
// That is the fact an approval rests on.  Every brokered command runs as this
// uid and /proc/<pid>/environ is readable within a uid, so a process the broker
// does not know about can read an approved run's token, exec with it set, and
// sudo on it.  The broker's own map cannot see that: a bounded drain that gave
// up, a run whose teardown it did not wait for, or its own restart all leave the
// map saying one thing and the process table another.  So before an approval
// takes, the map is checked against the kernel here.
//
// Fails closed on every path it cannot answer: an unreadable /proc is not
// evidence of quiet.
func (e *Executor) quiescence() map[string]any {
	strays, err := e.strays()
	if err != nil {
		return map[string]any{"quiescent": false, "detail": fmt.Sprintf(
			"this host's process table could not be read (%v), so nothing can say "+
				"whether anything is running as the executor", err)}
	}
	if len(strays) == 0 {
		return map[string]any{"quiescent": true, "detail": "nothing is running as the executor"}
	}
	log.Printf("not quiescent: %d process(es) of this uid outside any run: %s",
		len(strays), strings.Join(strays, ", "))
	return map[string]any{"quiescent": false, "detail": fmt.Sprintf(
		"%d process(es) are running as the executor outside any brokered command "+
			"(%s)", len(strays), listSome(strays, maxNamedStrays))}
}

// strays is every process of this uid that belongs neither to this daemon nor to
// a run it is confining, named for a person, longest-standing order not being
// interesting here.
func (e *Executor) strays() ([]string, error) {
	ours := os.Getuid()
	accounted := map[int]bool{os.Getpid(): true}
	e.liveMu.Lock()
	for c := range e.live {
		for _, pid := range c.pids() {
			accounted[pid] = true
		}
	}
	e.liveMu.Unlock()

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}
	var strays []string
	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || accounted[pid] {
			continue
		}
		info, err := os.Stat(filepath.Join("/proc", entry.Name()))
		if err != nil {
			continue // exited between the listing and the stat
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || int(st.Uid) != ours {
			continue
		}
		if !hasUserspace(pid) {
			// A kernel thread or a zombie: no address space, so no environment to read
			// a token out of and nothing to exec sudo with.  It cannot ride an
			// approval, and counting it would make a host permanently un-quiet for a
			// process that is not a process in the sense this is asking about.
			continue
		}
		strays = append(strays, entry.Name()+" ("+strings.TrimSpace(comm(pid))+")")
	}
	sort.Strings(strays)
	return strays, nil
}

// maxNamedStrays bounds what the refusal names.  The whole list is in the
// executor's log; the operator reads this one off a terminal, and a message that
// fills a screen is one that says less than a short one.
const maxNamedStrays = 5

func listSome(items []string, limit int) string {
	if len(items) <= limit {
		return strings.Join(items, ", ")
	}
	return fmt.Sprintf("%s and %d more; the executor's log has all of them",
		strings.Join(items[:limit], ", "), len(items)-limit)
}

// hasUserspace reports whether a pid has an address space of its own.  A kernel
// thread's cmdline is empty, and so is a zombie's; neither can read an environ
// or exec anything.
func hasUserspace(pid int) bool {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "cmdline"))
	return err == nil && len(data) > 0
}

// comm is a pid's executable name, for a message a person reads.  Best effort:
// the name is not what the decision rests on.
func comm(pid int) string {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "comm"))
	if err != nil {
		return "?"
	}
	return string(data)
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
