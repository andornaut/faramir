package hostfs

// Creating directories.

import (
	"os"
	"path/filepath"
	"testing"
)

// Every level created goes to the owner, not just the leaf: an intermediate
// left root-owned is a path its owner cannot traverse.
func TestEnsureDirCreatesEveryLevel(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "config", "sops", "age")
	changed, err := FS{}.EnsureDir(leaf, 0o700, Keep, Keep, true)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("creating a directory reported no change")
	}
	// Ancestors get traversal, the leaf what was asked for: the secrets directory's
	// 2770 on its parent would let the shared group rename the secrets directory.
	for _, tc := range []struct {
		dir  string
		want os.FileMode
	}{
		{filepath.Join(root, "config"), 0o755},
		{filepath.Join(root, "config", "sops"), 0o755},
		{leaf, 0o700},
	} {
		info, err := os.Stat(tc.dir)
		if err != nil {
			t.Fatalf("%s: %v", tc.dir, err)
		}
		if info.Mode().Perm() != tc.want {
			t.Errorf("%s is %o, want %o", tc.dir, info.Mode().Perm(), tc.want)
		}
	}
}

// The store's mode must not land on its parent, which would give the shared
// group rename on the directory holding every managed credential.
func TestEnsureDirDoesNotWidenAncestors(t *testing.T) {
	root := t.TempDir()
	store := filepath.Join(root, "faramir", "secrets")
	if _, err := (FS{}).EnsureDir(store, 0o2770|os.ModeSetgid, Keep, Keep, true); err != nil {
		t.Fatal(err)
	}
	parent, err := os.Stat(filepath.Join(root, "faramir"))
	if err != nil {
		t.Fatal(err)
	}
	if parent.Mode().Perm()&0o020 != 0 {
		t.Errorf("the secrets directory's parent is group-writable (%o)", parent.Mode().Perm())
	}
	if parent.Mode()&os.ModeSetgid != 0 {
		t.Error("the secrets directory's parent is setgid")
	}
}

// A second run reports nothing, which is what the changed flag is for.
func TestEnsureDirIsIdempotent(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "store")
	if _, err := (FS{}).EnsureDir(leaf, 0o2770|os.ModeSetgid, Keep, Keep, true); err != nil {
		t.Fatal(err)
	}
	changed, err := FS{}.EnsureDir(leaf, 0o2770|os.ModeSetgid, Keep, Keep, true)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a second run reported a change it did not make")
	}
}
