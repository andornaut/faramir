package sharetree

import (
	"os"
	"os/user"
	"path/filepath"
	"reflect"
	"syscall"
	"testing"
)

// "g+rwX": a directory needs group execute to be entered, a file gets it only if
// it was executable already.
func TestGroupShared(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   os.FileMode
		want os.FileMode
	}{
		{"a plain file gains group read and write only", 0o644, 0o664},
		{"an executable file keeps its execute bit", 0o755, 0o775},
		{"a file executable only for its owner still counts", 0o700, 0o770},
		{"a directory gains execute and setgid", os.ModeDir | 0o755, os.ModeDir | os.ModeSetgid | 0o775},
		{"a private directory is opened to the group", os.ModeDir | 0o700, os.ModeDir | os.ModeSetgid | 0o770},
		{"already shared is unchanged", 0o664, 0o664},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := groupShared(tc.in); got != tc.want {
				t.Errorf("groupShared(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// From the home down to the tree's parent; the tree itself is group-owned rather
// than traversed.
func TestComponents(t *testing.T) {
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

// A string comparison would put /home/op2 under /home/op.
func TestWithinComparesPathElements(t *testing.T) {
	for _, tc := range []struct {
		home, dir string
		want      bool
	}{
		{"/home/op", "/home/op/src", true},
		{"/home/op", "/home/op", true},
		{"/home/op", "/home/op2/src", false},
		{"/home/op", "/srv/faramir/tree", false},
	} {
		if got := within(tc.home, tc.dir); got != tc.want {
			t.Errorf("within(%q, %q) = %v, want %v", tc.home, tc.dir, got, tc.want)
		}
	}
}

// The sharing half needs no root: a tree the caller owns.
func TestShareTreeAppliesModesThroughout(t *testing.T) {
	root := t.TempDir()
	sub := filepath.Join(root, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(sub, "notes.txt")
	if err := os.WriteFile(plain, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(sub, "run.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o700); err != nil {
		t.Fatal(err)
	}

	// A file whose mode the caller asked to keep: shared by group but not
	// widened, which is what the files an enrolment writes need.
	kept := filepath.Join(root, "kept.json")
	if err := os.WriteFile(kept, []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	// -1 keeps the group, so no privilege is needed.
	if _, err := shareTree(root, -1, map[string]bool{"kept.json": true}, nil); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(kept); err != nil {
		t.Fatal(err)
	} else if info.Mode().Perm() != 0o640 {
		t.Errorf("kept.json is %o, want 640: sharing widened a mode its writer chose", info.Mode().Perm())
	}

	for _, tc := range []struct {
		path string
		want os.FileMode
	}{
		{sub, os.ModeDir | os.ModeSetgid | 0o770},
		{plain, 0o660},
		{script, 0o770},
	} {
		info, err := os.Stat(tc.path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != tc.want {
			t.Errorf("%s = %v, want %v", filepath.Base(tc.path), info.Mode(), tc.want)
		}
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
			got, err := traversalAction(info, tc.gid)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("traversalAction(%v, gid=%d) = %v, want %v", tc.mode, tc.gid, got, tc.want)
			}
		})
	}
}

// A regrouped directory hands the incoming group execute and nothing else. The
// group bits on the way in were the previous group's: carrying them over would
// give the executor read on a 0750 home and write on a 0770 one.
func TestTraversalMode(t *testing.T) {
	for _, tc := range []struct {
		name      string
		in        os.FileMode
		regrouped bool
		want      os.FileMode
	}{
		// Same group already: the bits it has are the ones it is meant to have, and
		// only traversal is missing.
		{"keeping the group adds execute alone", 0o700, false, 0o710},
		{"keeping the group leaves its read in place", 0o750, false, 0o750},
		{"keeping the group leaves its write in place", 0o770, false, 0o770},
		// Taken over from another group, which loses everything it had.
		{"a regroup grants execute", 0o700, true, 0o710},
		{"a regroup drops the group's read", 0o750, true, 0o710},
		{"a regroup drops the group's read and write", 0o770, true, 0o710},
		{"a regroup leaves the owner alone", 0o500, true, 0o510},
		{"a regroup leaves other alone", 0o771, true, 0o711},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := traversalMode(tc.in, tc.regrouped); got != tc.want {
				t.Errorf("traversalMode(%o, regrouped=%v) = %o, want %o",
					tc.in, tc.regrouped, got, tc.want)
			}
		})
	}
}

// Execute only: read would let these uids list the agent account's home rather than
// pass through it. The group is the tree's own, so nothing is regrouped and no
// privilege is needed; TestTraversalAction covers that branch.
func TestGrantTraversalAddsExecuteAndNotRead(t *testing.T) {
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

	if _, err := grantTraversal(home, tree, Options{Group: "shared"}, int(st.Gid)); err != nil {
		t.Fatal(err)
	}

	for _, dir := range []string{home, middle} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o710 {
			t.Errorf("%s is %o, want 0710: execute for the group, no read", dir, got)
		}
	}
	// The tree is not on the path to itself: Reachable leaves it as it was.
	info, err := os.Stat(tree)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("the tree itself was changed to %o", got)
	}
}

// What Share reports is what it altered, not that it ran. The first run
// rewrites the ownership and mode of every file in a tree; every run after it
// re-applies what is already there. A caller reporting "changed" reads this,
// so answering the same both times says a tree it just regrouped was left
// alone.
func TestShareReportsWhatItAltered(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot name this account")
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Skip("cannot name this account's group")
	}
	// The only test here that drives the exported Share, which grants traversal
	// from the agent account's home down to the tree. With TMPDIR inside the home,
	// that is the real home: a 0700 one becomes 0710, and one whose group is not
	// the primary group is regrouped and loses its group bits. An environment
	// guard, not a skip on the branch that would have failed.
	if home, err := Resolve(me.HomeDir); err == nil {
		if tmp, err := Resolve(os.TempDir()); err == nil && within(home, tmp) {
			t.Skipf("TMPDIR (%s) is inside %s, and this grants traversal from the "+
				"home down: running it here would chmod the real home", tmp, home)
		}
	}
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "src", "main.go"), []byte("package main\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	opts := Options{Dir: root, Operator: me.Username, Group: group.Name}

	first, err := Share(opts)
	if err != nil {
		t.Fatal(err)
	}
	// Three paths need widening here: the root, src, and main.go. A bound
	// rather than "more than nothing", which the root alone satisfies and which
	// would pass with the walk counting nothing at all.
	if first.Changed < 3 {
		t.Errorf("sharing a tree for the first time reported %d path(s) altered, "+
			"want at least the root, src and src/main.go", first.Changed)
	}

	second, err := Share(opts)
	if err != nil {
		t.Fatal(err)
	}
	if second.Changed != 0 {
		t.Errorf("re-applying reported %d path(s) altered, want 0: a second run "+
			"finds what the first left", second.Changed)
	}
}

// A path needing both a regroup and a widen is one path. Counting the
// operations instead would report a hundred files as two hundred, and the count
// is what an operator reads.
func TestASharedPathIsCountedOnceHoweverManyThingsItNeeds(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil || len(groups) < 2 {
		t.Skip("this account has no second group to move a file into")
	}
	gid := -1
	for _, candidate := range groups {
		if candidate != os.Getgid() {
			gid = candidate
			break
		}
	}
	if gid < 0 {
		t.Skip("this account has no second group to move a file into")
	}

	root := t.TempDir()
	file := filepath.Join(root, "notes.txt")
	if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Both paths need both things: the group is not the one being shared with,
	// and neither mode carries the group bits.
	changed, err := shareTree(root, gid, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 2 {
		t.Errorf("counted %d, want 2: the root and notes.txt, each needing a "+
			"regroup and a widen and each being one path", changed)
	}
}

// chown's "leave it as it is" alters nothing, so it counts as nothing.
func TestKeepingTheGroupIsNotAChange(t *testing.T) {
	root := t.TempDir()
	if err := os.Chmod(root, 0o2770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	changed, err := shareTree(root, -1, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Errorf("counted %d, want 0: nothing was regrouped and the mode was "+
			"already what sharing wants", changed)
	}
}

// The bits Chmod applies, which is what a comparison deciding "did this run
// alter the path" has to look at. Permissions alone would miss a setuid or
// sticky bit the chmod is about to clear, and report a path it changed as one
// it left alone; whole modes would count ModeDir and call every run a change.
func TestChmodBitsAreTheOnesChmodApplies(t *testing.T) {
	for _, tc := range []struct {
		name string
		in   os.FileMode
		want os.FileMode
	}{
		{"permissions survive", 0o751, 0o751},
		{"setgid survives", os.ModeSetgid | 0o770, os.ModeSetgid | 0o770},
		{"setuid survives", os.ModeSetuid | 0o755, os.ModeSetuid | 0o755},
		{"sticky survives", os.ModeSticky | 0o777, os.ModeSticky | 0o777},
		{"the directory bit is not a permission", os.ModeDir | 0o755, 0o755},
		{"nor is the symlink bit", os.ModeSymlink | 0o777, 0o777},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := chmodBits(tc.in); got != tc.want {
				t.Errorf("chmodBits(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// A directory holding a file an enrolment wrote is sticky, so unlink and rename
// there are the file's owner's alone. Without it the client group has rwx on
// the directory and can delete .claude/settings.json and put its own there,
// whatever mode the file itself carries.
func TestDirectoriesHoldingAKeptFileAreSticky(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, rel := range []string{".claude/settings.json", ".mcp.json"} {
		if err := os.WriteFile(filepath.Join(root, rel), []byte("{}\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "src"), 0o755); err != nil {
		t.Fatal(err)
	}

	keep := map[string]bool{".claude/settings.json": true, ".mcp.json": true}
	sticky := stickyDirs([]string{".claude/settings.json", ".mcp.json"})
	if _, err := shareTree(root, -1, keep, sticky); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		dir  string
		want bool
	}{
		{filepath.Join(root, ".claude"), true}, // holds settings.json
		// The root holds .mcp.json and is left alone anyway: sticky there would
		// stop a brokered command renaming over any operator-owned file at the
		// top level, which is what a tool rewriting a lock file does.
		{root, false},
		{filepath.Join(root, "src"), false}, // ordinary work goes on here
	} {
		info, err := os.Stat(tc.dir)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode()&os.ModeSticky != 0; got != tc.want {
			t.Errorf("%s sticky = %v, want %v (mode %v)",
				filepath.Base(tc.dir), got, tc.want, info.Mode())
		}
		// Still shared: sticky restricts unlink, it does not close the directory.
		if info.Mode().Perm()&0o070 != 0o070 {
			t.Errorf("%s is %04o: the client group cannot work in it",
				filepath.Base(tc.dir), info.Mode().Perm())
		}
	}
}

// The tree's own root is not in the set, so nothing at the top level of an
// enrolled tree stops being renamable by a brokered command. Stated as a test
// because it is a trade and not an oversight: what it costs is that the
// directory holding an agent's settings can itself be moved aside from a root
// the client group can write.
func TestTheTreeRootIsNotSticky(t *testing.T) {
	got := stickyDirs([]string{".mcp.json", "AGENTS.md", ".claude/settings.json",
		".opencode/plugins/faramir.js"})

	if got["."] {
		t.Error("the tree root is sticky, which stops a brokered command renaming " +
			"over any operator-owned file at the top level")
	}
	for _, want := range []string{".claude", ".opencode/plugins"} {
		if !got[want] {
			t.Errorf("%s is not sticky, so its settings can be unlinked", want)
		}
	}
}

// Applied once and not again: a second run finds the sticky bit already there.
func TestStickyIsNotAChangeOnASecondRun(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(root, ".claude", "settings.json"), []byte("{}\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	keep := map[string]bool{".claude/settings.json": true}
	sticky := stickyDirs([]string{".claude/settings.json"})

	if _, err := shareTree(root, -1, keep, sticky); err != nil {
		t.Fatal(err)
	}
	changed, err := shareTree(root, -1, keep, sticky)
	if err != nil {
		t.Fatal(err)
	}
	if changed != 0 {
		t.Errorf("a second run altered %d path(s), want 0", changed)
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
	if _, err := grantTraversal(home, tree, Options{Group: "shared"}, int(st.Gid)); err == nil {
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
func TestGrantTraversalOnTheHomeItselfDoesNothing(t *testing.T) {
	home := t.TempDir()
	if err := os.Chmod(home, 0o700); err != nil {
		t.Fatal(err)
	}
	var st syscall.Stat_t
	if err := syscall.Stat(home, &st); err != nil {
		t.Fatal(err)
	}

	changed, err := grantTraversal(home, home, Options{Group: "shared"}, int(st.Gid))
	if err != nil {
		t.Fatalf("granting traversal on the home itself: %v", err)
	}
	if changed != 0 {
		t.Errorf("granted %d, want 0", changed)
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
