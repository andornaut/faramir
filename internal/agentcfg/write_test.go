package agentcfg

// Writing the files: whose they are and where a link may carry a write.

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostfs"
)

// An agent's settings are a file faramir edits rather than owns, and both
// commands run as root on a path the account the agent runs as can write. One
// that is not the operator's fails the run: editing it would be root writing a
// file it was never asked to, and chowning it to make that true would take it
// from whoever has it.
func TestAgentSettingsNotOwnedByTheOperatorFailTheRun(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const before = "{}\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	render := func(File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	// An operator that is not this file's owner, which is what the check asks.
	_, _, err := WriteFiles(
		hostfs.FS{}, nil, home, "", os.Getuid()+1, hostfs.Keep, 0o700, false, render, files)

	if !errors.Is(err, hostfs.ErrNotOperators) {
		t.Fatalf("err = %v, want the file refused", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was written anyway:\n%s", body)
	}
}

// A symlinked one is followed to what it points at, as the credentials section
// is: a dotfiles manager keeps such a file as a link, and the merge reads
// through a link before renaming a new file over it.
func TestSymlinkedAgentSettingsAreWrittenThroughToTheirTarget(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "dotfiles-settings.json")
	if err := os.WriteFile(target, []byte(`{"model":"mine"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	render := func(File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	if _, _, err := WriteFiles(
		hostfs.FS{}, nil, home, "", os.Getuid(), hostfs.Keep, 0o700, false, render, files); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced with a regular file")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"a": 1`) {
		t.Errorf("the target did not get faramir's keys:\n%s", body)
	}
	if !strings.Contains(string(body), `"model": "mine"`) {
		t.Errorf("the operator's own keys were lost:\n%s", body)
	}
}

// The same path twice is one file written once, which is what two agents
// reading one file of their own is. Only two different paths landing on one
// are two writes with one survivor, so a repeat must not be refused with them.
func TestRefusingOneFileTwiceAllowsTheSamePathTwice(t *testing.T) {
	home := t.TempDir()
	const rel = ".claude/CLAUDE.md"
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, rel), []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	refused := RefuseUnwritable(hostfs.FS{}, home, os.Getuid(), "", []string{rel, rel})

	if len(refused) > 0 {
		t.Errorf("one path named twice was refused as two files: %v", refused)
	}
}

// The bound is on the directory, not the file: Lstat declines to follow only
// the last component, so a symlinked parent would carry the write out of the
// tree before the leaf is looked at. Blocked at the directory, which is the
// level a run reaches first.
func TestASymlinkedParentCannotCarryTheWriteOutOfTheTree(t *testing.T) {
	outside := t.TempDir()
	const before = "{}\n"
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	tree := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, ".claude")); err != nil {
		t.Fatal(err)
	}

	_, _, err := WriteFiles(hostfs.FS{}, nil, tree, "", os.Getuid(), os.Getgid(),
		0o2770|os.ModeSetgid, true, render, files)

	if err == nil {
		t.Fatal("a write through a symlinked parent was accepted")
	}
	if !strings.Contains(err.Error(), filepath.Join(tree, ".claude")) {
		t.Errorf("the error does not name the link: %v", err)
	}
	info, statErr := os.Stat(filepath.Join(outside, "settings.json"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the file outside the tree is %04o, want the 0600 it had: the "+
			"tree's mode reached it", info.Mode().Perm())
	}
}

// Creation is bounded the same way: a file this run makes lands in that
// directory as surely as one it edits.
func TestASymlinkedParentCannotCarryACreationOutOfTheTree(t *testing.T) {
	outside := t.TempDir()
	tree := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, ".claude")); err != nil {
		t.Fatal(err)
	}
	render := func(File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	_, _, err := WriteFiles(hostfs.FS{}, nil, tree, "", os.Getuid(), os.Getgid(),
		0o2770|os.ModeSetgid, true, render, files)

	if err == nil {
		t.Fatal("a creation through a symlinked parent was accepted")
	}
	if hostfs.Exists(filepath.Join(outside, "settings.json")) {
		t.Error("a file was created outside the tree being enrolled")
	}
}

// A home has no such bound, a dotfiles repository being wherever the operator
// keeps it, and that is what makes the case above a bound rather than a ban.
func TestASymlinkedParentIsFollowedInAHome(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	render := func(File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	if _, _, err := WriteFiles(hostfs.FS{}, nil, home, "", os.Getuid(), os.Getgid(),
		0o700, false, render, files); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(outside, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"a": 1`) {
		t.Errorf("the dotfiles copy did not get faramir's keys:\n%s", body)
	}
}
