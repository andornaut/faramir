package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The broker prints its --check report on stdout and logs on stderr, and it
// logs on every load whether or not anything went wrong.  A combined capture
// puts a log line in front of the JSON, so every report fails to parse and a
// working host reports itself broken.
func TestCommandReturnsStdoutOnly(t *testing.T) {
	run := &runner{}
	out, err := run.command("sh", "-c", `echo "loaded 3 secret refs" >&2; echo '{"ok":true}'`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "loaded 3 secret refs") {
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

// Creating a directory has to give every level it created to the owner, not
// just the leaf.  An intermediate left root-owned at the leaf's mode is a path
// its owner cannot traverse, and the only symptom is sops reporting that it
// found no key.
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
	for _, dir := range []string{
		filepath.Join(root, "config"),
		filepath.Join(root, "config", "sops"),
		leaf,
	} {
		info, err := os.Stat(dir)
		if err != nil {
			t.Fatalf("%s: %v", dir, err)
		}
		if info.Mode().Perm() != 0o700 {
			t.Errorf("%s is %o, want 700", dir, info.Mode().Perm())
		}
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

// A second run must report nothing, which is the whole reason the report has a
// changed flag: a configuration manager reads it rather than stat-ing the host.
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
