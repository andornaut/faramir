package escalation

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// The walk the PAM helper makes, from the sudo being decided up towards the
// command the executor forked. The kernel's account of who forked whom: a
// process does not write its own ancestry, which is what makes it worth asking
// about.

// parentOf reads the ppid out of /proc/<pid>/stat, or reports that there is no
// such process to read. The executable name is field two, in brackets, and can
// hold spaces and parentheses, so the scan starts after the last ')' and ppid is
// the second field after it.
func parentOf(pid int) (int, bool) {
	data, err := os.ReadFile(filepath.Join("/proc", strconv.Itoa(pid), "stat"))
	if err != nil {
		return 0, false
	}
	end := bytes.LastIndexByte(data, ')')
	if end < 0 {
		return 0, false
	}
	fields := strings.Fields(string(data)[end+1:])
	// state, ppid: the two fields after the name.
	if len(fields) < 2 {
		return 0, false
	}
	parent, err := strconv.Atoi(fields[1])
	if err != nil {
		return 0, false
	}
	return parent, true
}

// maxAncestors bounds the walk, a cycle in /proc otherwise spinning. Generous
// rather than tight: the walk has to reach the process the executor forked, which
// sits at the top of the run's tree, and a run that nests make inside a shell
// inside a wrapper puts real depth between the two. A bound reached early is a
// sudo refused as unowned with nothing naming the depth as the cause, and each
// step costs one read of a file already in the page cache.
const maxAncestors = 256

// Ancestry is pid and every process above it, as far as the walk reaches. The
// chain rather than one process, because what the executor forked sits somewhere
// above the sudo being decided and neither end knows how far.
//
// It climbs past the run to pid 1, which is not a problem and not avoidable: this
// runs as root inside sudo, /proc/<pid>/stat stays world-readable under
// PR_SET_DUMPABLE=0, and ProtectProc= bounds the executor's own view of /proc
// rather than anyone else's view of the executor. So the chain carries the
// daemons and init as well. They match nothing: the executor answers only for a
// process it forked and still holds a handle on.
func Ancestry(pid int) []int {
	out := make([]int, 0, 8)
	for range maxAncestors {
		if pid <= 1 {
			return out
		}
		out = append(out, pid)
		parent, ok := parentOf(pid)
		if !ok {
			return out
		}
		pid = parent
	}
	return out
}
