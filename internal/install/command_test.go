package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The broker prints its --check report on stdout and logs on stderr on every
// load, so a combined capture makes every report unparseable.
func TestCommandReturnsStdoutOnly(t *testing.T) {
	run := &runner{}
	out, err := run.command("sh", "-c", `echo "loaded 3 vault refs" >&2; echo '{"ok":true}'`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "loaded 3 vault refs") {
		t.Fatalf("stderr leaked into stdout: %q", out)
	}
	var report struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout did not parse on its own: %v", err)
	}
	if !report.OK {
		t.Error("wrong value parsed")
	}
}

// A failure has to carry stderr, which is where the reason is.
func TestCommandErrorCarriesStderr(t *testing.T) {
	run := &runner{}
	_, err := run.command("sh", "-c", `echo "the reason" >&2; exit 3`)
	if err == nil {
		t.Fatal("no error from a command that exited 3")
	}
	if !strings.Contains(err.Error(), "the reason") {
		t.Errorf("error does not carry stderr: %v", err)
	}
}

// Every level created goes to the owner, not just the leaf: an intermediate
// left root-owned is a path its owner cannot traverse.
func TestEnsureDirCreatesEveryLevel(t *testing.T) {
	root := t.TempDir()
	leaf := filepath.Join(root, "config", "sops", "age")
	changed, err := fsys{}.ensureDir(leaf, 0o700, keep, keep, true)
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
	if _, err := (fsys{}).ensureDir(store, 0o2770|os.ModeSetgid, keep, keep, true); err != nil {
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

func TestMissingAncestors(t *testing.T) {
	root := t.TempDir()
	got := missingAncestors(filepath.Join(root, "a", "b"))
	want := []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// An existing directory needs nothing created.
	if leftovers := missingAncestors(root); len(leftovers) != 0 {
		t.Errorf("got %v for a directory that is already there", leftovers)
	}
}

// A second run reports nothing, which is what the changed flag is for.
func TestEnsureDirIsIdempotent(t *testing.T) {
	leaf := filepath.Join(t.TempDir(), "store")
	if _, err := (fsys{}).ensureDir(leaf, 0o2770|os.ModeSetgid, keep, keep, true); err != nil {
		t.Fatal(err)
	}
	changed, err := fsys{}.ensureDir(leaf, 0o2770|os.ModeSetgid, keep, keep, true)
	if err != nil {
		t.Fatal(err)
	}
	if changed {
		t.Error("a second run reported a change it did not make")
	}
}
