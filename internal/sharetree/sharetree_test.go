package sharetree

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// "g+rwX", where the X is the part worth pinning: a directory needs group
// execute to be entered, and a file gets it only if it was executable already.
// Granting it unconditionally would mark every ordinary file in a tree runnable.
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
			if got := GroupShared(tc.in); got != tc.want {
				t.Errorf("GroupShared(%v) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// Every directory from the home down to the tree's parent, and not the tree
// itself: that one is group-owned rather than traversed.
func TestComponents(t *testing.T) {
	home := "/home/op"
	got := Components(home, "/home/op/src/github.com/x/repo")
	want := []string{"/home/op", "/home/op/src", "/home/op/src/github.com", "/home/op/src/github.com/x"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Components = %v, want %v", got, want)
	}
	// A tree that is the home itself needs nothing walked.
	if got := Components(home, home); len(got) != 0 {
		t.Errorf("Components(home, home) = %v, want none", got)
	}
	// One level down is just the home.
	if got := Components(home, "/home/op/tree"); !reflect.DeepEqual(got, []string{home}) {
		t.Errorf("Components = %v, want [%s]", got, home)
	}
}

// A sibling whose name starts with the home's is not inside it. Comparing as
// strings would put /home/op2 under /home/op and walk the wrong directories.
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

// The read-back that catches a filesystem accepting one ACL and silently
// dropping later edits. Anything not named in the listing is missing.
func TestMissingFrom(t *testing.T) {
	acl := "user::rwx\nuser:faramir-exec:--x\ngroup::---\nmask::--x\nother::---\n"
	got := MissingFrom(acl, []string{"faramir-exec", "faramir-broker"})
	if !reflect.DeepEqual(got, []string{"faramir-broker"}) {
		t.Errorf("MissingFrom = %v, want [faramir-broker]", got)
	}
	if got := MissingFrom(acl, []string{"faramir-exec"}); got != nil {
		t.Errorf("MissingFrom = %v, want none", got)
	}
	// A prefix is not a match: faramir-exec must not satisfy faramir-exec2.
	if got := MissingFrom(acl, []string{"faramir-exec2"}); len(got) != 1 {
		t.Errorf("MissingFrom matched a prefix: %v", got)
	}
}

// The sharing half needs no root, so it is exercised directly: a tree the
// caller owns, with a file and a subdirectory in it.
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

	// -1 keeps the group, so this needs no privilege.
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
