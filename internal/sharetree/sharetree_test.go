package sharetree

import (
	"os"
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

	// -1 keeps the group, so no privilege is needed.
	if err := shareTree(root, -1); err != nil {
		t.Fatal(err)
	}

	for path, want := range map[string]os.FileMode{
		sub:    os.ModeDir | os.ModeSetgid | 0o770,
		plain:  0o660,
		script: 0o770,
	} {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode() != want {
			t.Errorf("%s = %v, want %v", filepath.Base(path), info.Mode(), want)
		}
	}
}

// What one directory on the path needs.  Group ownership rather than an ACL, the
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
			got, err := traversalAction(info, tc.gid, dir)
			if err != nil {
				t.Fatal(err)
			}
			if got != tc.want {
				t.Errorf("traversalAction(%v, gid=%d) = %v, want %v", tc.mode, tc.gid, got, tc.want)
			}
		})
	}
}

// Execute only: read would let these uids list the operator's home rather than
// pass through it.  The group is the tree's own, so nothing is regrouped and no
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

	if err := grantTraversal(home, tree, Options{Group: "shared"}, int(st.Gid)); err != nil {
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
