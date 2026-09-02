package sharetree

import (
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"syscall"
	"testing"
)

// From the home down to the tree's parent; the tree itself is group-owned rather
// than traversed.
func TestComponentsWalkFromTheHomeToTheTreesParent(t *testing.T) {
	home := "/home/op"
	got := components(home, "/home/op/src/github.com/x/repo")
	want := []string{"/home/op", "/home/op/src", "/home/op/src/github.com", "/home/op/src/github.com/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("components = %v, want %v", got, want)
	}
	// A tree that is the home needs nothing walked.
	if got := components(home, home); len(got) != 0 {
		t.Errorf("components(home, home) = %v, want none", got)
	}
	// One level down is just the home.
	if got := components(home, "/home/op/tree"); !reflect.DeepEqual(got, []string{home}) {
		t.Errorf("components = %v, want [%s]", got, home)
	}
}

// What one directory on the path needs. Group ownership rather than an ACL, the
// group slot being the one going spare on a home the operator owns.
func TestTraversalAction(t *testing.T) {
	dir := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	mine := int(st.Gid)
	other := mine + 1

	for _, tc := range []struct {
		name string
		mode os.FileMode
		gid  int
		want traversal
	}{
		// Already open to everyone, and tightening it is not this command's
		// business.
		{"world-traversable is left alone", 0o755, other, leaveAlone},
		{"world-traversable even with a foreign group", 0o701, other, leaveAlone},
		// Right group, only the bit missing.
		{"our group without execute gains it", 0o700, mine, addExecute},
		{"our group with execute is done", 0o710, mine, leaveAlone},
		// Wrong group, which costs the old group its access.
		{"a foreign group is taken over", 0o700, other, regroup},
		{"a foreign group with execute is still taken over", 0o710, other, regroup},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			info, err := os.Stat(dir)
			if err != nil {
				t.Fatal(err)
			}
			got, err := traversalAction(info, groupEntrant(tc.gid))
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("traversalAction(%v, gid=%d) = %v, want %v", tc.mode, tc.gid, got, tc.want)
			}
		})
	}
}

// Every directory on the path that the group cannot enter is named, and none of
// them is altered: they are the operator's, and opening them is not faramir's
// to do. The group is the tree's own, so no privilege is needed here;
// TestTraversalAction covers the regroup branch.
func TestBlockersNamesThePathAndChangesNothing(t *testing.T) {
	home := t.TempDir()
	middle := filepath.Join(home, "src")
	tree := filepath.Join(middle, "work")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil {
		t.Fatal(err)
	}
	for _, dir := range []string{home, middle} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}

	blocked, err := blockers(home, tree, groupEntrant(int(st.Gid)))
	if err != nil {
		t.Fatal(err)
	}

	got := make([]string, 0, len(blocked))
	for _, b := range blocked {
		got = append(got, b.Path)
	}
	want := []string{home, middle}
	if !slices.Equal(got, want) {
		t.Errorf("blocked %v, want %v", got, want)
	}
	// The tree is not on the path to itself, and nothing on the path was opened.
	for _, dir := range []string{home, middle, tree} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("%s is %o, want 0700: a check altered it", dir, got)
		}
	}
}

// Traversal is granted through descriptors, so a component swapped after it was
// looked at reaches nothing. These directories are the operator's and this
// runs as root: chmod and chown follow a link, so a path checked and then acted
// on by name is root regrouping a directory of somebody else's choosing.
func TestGrantTraversalDoesNotFollowASwappedComponent(t *testing.T) {
	home := t.TempDir()
	realDir := filepath.Join(home, "src")
	tree := filepath.Join(realDir, "work")
	if err := os.MkdirAll(tree, 0o700); err != nil {
		t.Fatal(err)
	}
	// What an attacker would aim at: a directory of somebody else's, not
	// traversable by the group, outside everything being shared.
	prize := filepath.Join(t.TempDir(), "prize")
	if err := os.MkdirAll(prize, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(prize)
	if err != nil {
		t.Fatal(err)
	}
	// The component is replaced by a link to it, as its owner could at any time.
	if err := os.Rename(realDir, filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(prize, realDir); err != nil {
		t.Fatal(err)
	}

	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil {
		t.Fatal(err)
	}
	// It fails rather than following: os.Root refuses a name that resolves
	// outside the directory it was opened on.
	if _, err := blockers(home, tree, groupEntrant(int(st.Gid))); err == nil {
		t.Error("a swapped component was walked into")
	}

	after, err := os.Stat(prize)
	if err != nil {
		t.Fatal(err)
	}
	if after.Mode() != before.Mode() {
		t.Errorf("the directory the link pointed at is now %v, was %v: root "+
			"chmodded somewhere it was never pointed", after.Mode(), before.Mode())
	}
}

// A tree that is the home has nothing above it to walk. components answers
// with none, and asking for the tail of that is asking for element one of an
// empty list.
func TestBlockersOnTheHomeItselfReportsNothing(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil {
		t.Fatal(err)
	}

	blocked, err := blockers(home, home, groupEntrant(int(st.Gid)))
	if err != nil {
		t.Fatalf("asking about the home itself: %v", err)
	}
	if len(blocked) != 0 {
		t.Errorf("reported %d, want 0", len(blocked))
	}
	info, err := os.Stat(home)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o700 {
		t.Errorf("the home is %04o, want the 0700 it had", info.Mode().Perm())
	}
}

// components is the walk list, and the last element of the path is never on
// it: whatever names a path grants it. Share sets the tree it is about to
// share, and `faramir link add` grants the file it is about to read, so a
// caller wanting the directories that hold a file names the file. Naming the
// directory instead stops one hop short and leaves the directory holding the
// file unenterable, which is a broker that cannot open a link it was told to
// serve.
func TestComponentsStopAboveTheLastElement(t *testing.T) {
	const home = "/home/op"
	for _, tc := range []struct {
		name, path string
		want       []string
	}{
		{"a linked file, whose own directory has to be entered",
			"/home/op/.config/gh/hosts.yml",
			[]string{home, "/home/op/.config", "/home/op/.config/gh"}},
		{"a linked file in the home itself", "/home/op/.npmrc", []string{home}},
		{"a tree, whose own step sets it", "/home/op/src/project", []string{home, "/home/op/src"}},
		{"the home itself, with nothing above it to walk", home, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := components(home, tc.path)
			if len(got) != len(tc.want) {
				t.Fatalf("components = %v, want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Errorf("components[%d] = %q, want %q", i, got[i], tc.want[i])
				}
			}
		})
	}
}

// A directory the account can already enter is not a blocker, whichever of its
// groups opens it. The broker is in its own group and in the client group, so
// asking the client group alone reports a path the broker walks every day as
// one it cannot reach, and hands the operator a chgrp that changes nothing.
func TestAnAccountIsAskedAboutEveryGroupItIsIn(t *testing.T) {
	dir := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	// Grouped to the account's own group, open to that group and to nobody
	// else: the arrangement the client group would be asked about and miss.
	if err := os.Chmod(dir, 0o710); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}

	const foreign = 1 // a gid the directory is not in
	mine := int(st.Gid)

	// Asked about a group that does not own it, this is a blocker.
	if got, err := traversalAction(info, groupEntrant(foreign)); err != nil || got == leaveAlone {
		t.Errorf("traversalAction for a foreign group = %v (%v), want it reported", got, err)
	}
	// Asked about an account that is in the owning group, it is not.
	who := entrant{uid: -1, gids: []int{foreign, mine}}
	if got, err := traversalAction(info, who); err != nil || got != leaveAlone {
		t.Errorf("traversalAction for an account in the owning group = %v (%v), want leaveAlone", got, err)
	}
	// And the owner's own execute bit answers for the owner.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if info, err = os.Stat(dir); err != nil {
		t.Fatal(err)
	}
	owner := entrant{uid: int(st.Uid), gids: []int{foreign}}
	if got, err := traversalAction(info, owner); err != nil || got != leaveAlone {
		t.Errorf("traversalAction for the owner = %v (%v), want leaveAlone", got, err)
	}
}

// The kernel takes the first class that matches and does not fall through: a
// directory whose group is the one being asked about is answered by the group
// bits alone, whatever the other bits say. Checking the world bit first called
// a directory at 0701 traversable by its own group, which cannot enter it, so
// an enrolment reported a tree reachable that the executor met with EACCES.
func TestTheOwningGroupIsAnsweredByItsOwnBits(t *testing.T) {
	dir := t.TempDir()
	var st syscall.Stat_t
	if err := syscall.Stat(dir, &st); err != nil {
		t.Fatal(err)
	}
	// Open to everyone but the group that owns it.
	if err := os.Chmod(dir, 0o701); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := traversalAction(info, groupEntrant(int(st.Gid))); err != nil || got == leaveAlone {
		t.Errorf("traversalAction for the owning group = %v (%v), want it reported: "+
			"the group bits are empty and the group is what was asked about", got, err)
	}
	// A group that does not own it is answered by the other bits, which are open.
	const foreign = 1
	if got, err := traversalAction(info, groupEntrant(foreign)); err != nil || got != leaveAlone {
		t.Errorf("traversalAction for a foreign group = %v (%v), want leaveAlone", got, err)
	}
}
