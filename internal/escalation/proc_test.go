package escalation

import (
	"os"
	"testing"
)

// The walk is the kernel's account of who forked whom. Skipped rather than
// failed where there is no /proc: the walk is Linux's, and so is every host this
// runs on.
func requireProc(t *testing.T) {
	t.Helper()
	if _, err := os.Stat("/proc/self/stat"); err != nil {
		t.Skip("no /proc; the walk cannot be checked here")
	}
}

func TestParentOfIsTheKernelsAnswer(t *testing.T) {
	requireProc(t)
	parent, ok := parentOf(os.Getpid())
	if !ok {
		t.Fatal("this process's parent could not be read")
	}
	if parent != os.Getppid() {
		t.Errorf("parentOf = %d, want %d", parent, os.Getppid())
	}
}

// Nothing is invented for a pid that is not there: the walk ends rather than
// reporting a process it could not read.
func TestAMissingProcessEndsTheWalk(t *testing.T) {
	requireProc(t)
	// Above the pid ceiling on any Linux, so no process can hold it.
	const absent = 1 << 30
	if parent, ok := parentOf(absent); ok {
		t.Errorf("parentOf(%d) = %d, want none", absent, parent)
	}
	if chain := Ancestry(absent); len(chain) != 1 || chain[0] != absent {
		t.Errorf("Ancestry(%d) = %v; the walk should report what it was asked about "+
			"and stop, the executor being what decides whether it is a run", absent, chain)
	}
}

// The walk climbs and stops. It ends at pid 1 rather than running past its
// bound, and reports each process once: a cycle in /proc would otherwise spin.
func TestAncestryClimbsAndTerminates(t *testing.T) {
	requireProc(t)
	chain := Ancestry(os.Getpid())
	if len(chain) == 0 {
		t.Fatal("the walk found nothing, starting from a live process")
	}
	if chain[0] != os.Getpid() {
		t.Errorf("the walk starts at %d, want this process (%d)", chain[0], os.Getpid())
	}
	if len(chain) > maxAncestors {
		t.Errorf("the walk reported %d processes, past its bound of %d", len(chain), maxAncestors)
	}
	seen := map[int]bool{}
	for _, pid := range chain {
		if seen[pid] {
			t.Fatalf("pid %d twice: the walk is going in a circle", pid)
		}
		seen[pid] = true
	}
	// pid 1 is nobody's brokered command, and the walk must not offer it as one.
	if seen[1] {
		t.Error("the walk reported pid 1, which no run forked")
	}
}
