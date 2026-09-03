package vault

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Only a file the config manages: anything else would write a file the broker
// never reads, outside the directory the secrets group protects.
func TestOnlyAManagedFileResolves(t *testing.T) {
	managed := []string{"/opt/store/ansible.sops.yml", "/opt/store/home.sops.yml"}

	for _, arg := range []string{
		"/opt/store/ansible.sops.yml",       // full path
		"ansible.sops.yml",                  // base name
		"/opt/store/../store/home.sops.yml", // cleaned to a managed path
	} {
		if _, err := Resolve(managed, arg); err != nil {
			t.Errorf("refused a managed file %q: %v", arg, err)
		}
	}

	for _, arg := range []string{
		"/etc/shadow",
		"/opt/store/../../etc/shadow",
		"unmanaged.sops.yml",
		"/opt/store/unmanaged.sops.yml",
	} {
		if got, err := Resolve(managed, arg); err == nil {
			t.Errorf("accepted %q, resolving to %q", arg, got)
		}
	}
}

// A distinct message, the fix being different: there is nothing to edit.
func TestNoManagedFilesSaysSo(t *testing.T) {
	_, err := Resolve(nil, "anything.sops.yml")
	if err == nil {
		t.Fatal("accepted an edit with no managed files")
	}
	if !strings.Contains(err.Error(), "no managed sops files") {
		t.Errorf("unhelpful message: %v", err)
	}
}

// Picking one would be picking which credential the operator meant to change.
func TestAnAmbiguousBaseNameIsRefused(t *testing.T) {
	managed := []string{"/opt/a/store.sops.yml", "/opt/b/store.sops.yml"}
	if _, err := Resolve(managed, "store.sops.yml"); err == nil {
		t.Error("resolved an ambiguous base name instead of refusing it")
	}
}

// A relative path would resolve through an inherited PATH.
func TestARelativeEditorIsRefused(t *testing.T) {
	if _, err := ResolveEditor("nano"); err == nil {
		t.Error("accepted a relative editor path")
	}
	if _, err := ResolveEditor("../../tmp/evil"); err == nil {
		t.Error("accepted a relative editor path")
	}
}

func TestARequestedEditorMustExist(t *testing.T) {
	if _, err := ResolveEditor("/nonexistent/editor"); err == nil {
		t.Error("accepted an editor that is not there")
	}
	// A root-owned program in a root-owned directory. Skipped where the host has
	// none.
	installed := ""
	for _, candidate := range append([]string{"/bin/cat", "/usr/bin/cat"}, Editors...) {
		if info, err := os.Stat(candidate); err == nil &&
			unsafeToRunAsRoot(candidate, info) == "" {
			installed = candidate
			break
		}
	}
	if installed == "" {
		t.Skip("no root-owned editor on this host to accept")
	}
	// Compared against the resolved path, not the one asked for: /bin is a
	// symlink to /usr/bin on a merged host, and what runs is the file the links
	// end at.
	want, err := filepath.EvalSymlinks(installed)
	if err != nil {
		t.Fatal(err)
	}
	got, err := ResolveEditor(installed)
	if err != nil || got != want {
		t.Errorf("resolveEditor(%q) = %q, %v; want %q", installed, got, err, want)
	}
}

// goodEditor is a root-owned program in root-owned directories, for the tests
// that need one that passes. Empty where the host has none.
func goodEditor(t *testing.T) string {
	t.Helper()
	for _, candidate := range append([]string{"/bin/cat", "/usr/bin/cat"}, Editors...) {
		if path, err := checkedEditor(candidate); err == nil {
			return path
		}
	}
	return ""
}

// The editor runs as root with the decrypted store open, so a file the operator
// can write is the operator choosing what runs as root.
func TestAnEditorTheOperatorCanWriteIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root every file below would be root-owned")
	}
	dir := t.TempDir()
	own := filepath.Join(dir, "ed")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveEditor(own); err == nil {
		t.Error("accepted an editor owned by the account invoking sudo")
	}
	// The directory counts too: write there is permission to replace it.
	if _, err := ResolveEditor(filepath.Join(dir, "missing")); err == nil {
		t.Error("accepted an editor in a directory the operator can write")
	}
}

// No candidate may be a wrapper that reads the environment or a dotfile to
// decide what to run, as sensible-editor and /usr/bin/editor do.
func TestTheCandidateEditorsAreRealEditors(t *testing.T) {
	for _, candidate := range Editors {
		if !filepath.IsAbs(candidate) {
			t.Errorf("candidate %q is not absolute", candidate)
		}
		switch filepath.Base(candidate) {
		case "editor", "sensible-editor", "select-editor":
			t.Errorf("candidate %q resolves through operator-writable configuration", candidate)
		}
	}
}

// Two edits of one managed file each decrypt their own copy. Whichever encrypts
// last would otherwise replace the other's work with a copy that never had it,
// and both would report the file written: a secret an operator had just saved,
// gone, with nothing said.
func TestAnEditIsRefusedWhenTheFileMovedUnderIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "app.sops.yml")
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := digestOf(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := unchangedSince(path, before); err != nil {
		t.Errorf("a file nothing touched was refused: %v", err)
	}

	if err := os.WriteFile(path, []byte("second\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	err = unchangedSince(path, before)
	if err == nil {
		t.Fatal("a file something else wrote was accepted")
	}
	for _, want := range []string{path, "changed while this was working on it", "again"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}

	// Same bytes written again is the same file: an editor that rewrites without
	// changing anything must not read as somebody else's write.
	if err := os.WriteFile(path, []byte("first\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := unchangedSince(path, before); err != nil {
		t.Errorf("identical contents were refused: %v", err)
	}
}

// $VISUAL before $EDITOR, both after --editor, and each held to the same check
// as a path typed on the command line. Honoured rather than ignored because the
// check is what makes a program safe to run as root over the decrypted store:
// an account that cannot write the binary or a directory above it cannot decide
// what runs, whichever source named it.
func TestVisualThenEditorChooseTheEditor(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	t.Setenv("VISUAL", good)
	t.Setenv("EDITOR", "/usr/bin/definitely-not-this")
	if got, err := ResolveEditor(""); err != nil || got != good {
		t.Errorf("$VISUAL was not used: resolveEditor(\"\") = %q, %v; want %q", got, err, good)
	}

	// $EDITOR alone is used, and --editor outranks both.
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", good)
	if got, err := ResolveEditor(""); err != nil || got != good {
		t.Errorf("$EDITOR was not used: resolveEditor(\"\") = %q, %v; want %q", got, err, good)
	}
	t.Setenv("EDITOR", "/usr/bin/definitely-not-this")
	if got, err := ResolveEditor(good); err != nil || got != good {
		t.Errorf("--editor did not outrank $EDITOR: got %q, %v", got, err)
	}
}

// A variable naming something unsafe is refused rather than passed over: it is
// the operator's own setting, and falling through to the list would open the
// store in an editor they did not ask for and say nothing about it.
func TestAnEditorFromTheEnvironmentIsHeldToTheSameCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the file below would be root-owned")
	}
	own := filepath.Join(t.TempDir(), "ed")
	if err := os.WriteFile(own, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"VISUAL", "EDITOR"} {
		t.Setenv("VISUAL", "")
		t.Setenv("EDITOR", "")
		t.Setenv(name, own)
		_, err := ResolveEditor("")
		if err == nil {
			t.Errorf("$%s named an editor this account can write and it was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), "$"+name) {
			t.Errorf("the refusal does not say $%s named it: %v", name, err)
		}
	}
}

// With nothing naming one, the built-in list decides. This is the stock host:
// sudo's env_reset drops both variables unless the sudoers keep them.
func TestTheBuiltInListIsUsedWhenNothingNamesAnEditor(t *testing.T) {
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	got, err := ResolveEditor("")
	if err != nil {
		t.Skipf("this host has none of %v", Editors)
	}
	want, err := filepath.EvalSymlinks(got)
	if err != nil || want != got {
		t.Errorf("resolveEditor returned %q, which is not a resolved path", got)
	}
	var found bool
	for _, candidate := range Editors {
		if resolved, err := filepath.EvalSymlinks(candidate); err == nil && resolved == got {
			found = true
		}
	}
	if !found {
		t.Errorf("resolveEditor chose %q, which is none of %v", got, Editors)
	}
}

// The list is held to the check as well, so no path reaches a root exec
// unexamined. The first that passes wins, not the first that exists.
func TestTheBuiltInListIsHeldToTheCheck(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("as root the file below would be root-owned")
	}
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	writable := filepath.Join(t.TempDir(), "ed")
	if err := os.WriteFile(writable, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("VISUAL", "")
	t.Setenv("EDITOR", "")
	restore := Editors
	t.Cleanup(func() { Editors = restore })
	Editors = []string{writable, good}

	if got, err := ResolveEditor(""); err != nil || got != good {
		t.Errorf("a candidate this account can write was taken: got %q, %v; want %q",
			got, err, good)
	}

	// And with nothing in the list that passes, the refusal says why rather than
	// reporting that no editor is installed.
	Editors = []string{writable}
	_, err := ResolveEditor("")
	if err == nil {
		t.Fatal("every candidate failed the check and one was still chosen")
	}
	if !strings.Contains(err.Error(), writable) {
		t.Errorf("the refusal does not name the candidate it turned down: %v", err)
	}
}

// "vim -u /somewhere/vimrc" is an ordinary thing to have in $EDITOR, and -u
// names a file of commands vim runs on startup. Passing arguments through would
// let whoever owns that file decide what root does while every ownership check
// still passed.
func TestAnEditorWithArgumentsIsRefused(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	for _, named := range []string{good + " -u /tmp/evil.vim", good + "\t--cmd :!sh"} {
		if _, err := ResolveEditor(named); err == nil {
			t.Errorf("accepted %q, so an argument reached a program running as root", named)
		}
	}
	t.Setenv("VISUAL", good+" -u /tmp/evil.vim")
	if _, err := ResolveEditor(""); err == nil {
		t.Error("accepted arguments from $VISUAL")
	}
}

// What is checked has to be what runs. Resolving afterwards would leave the
// links in between deciding it: /usr/bin/vi is an alternatives symlink on a
// Debian host, and the file it names is not the one an ownership check of
// /usr/bin/vi reads.
func TestTheEditorThatRunsIsTheResolvedPath(t *testing.T) {
	good := goodEditor(t)
	if good == "" {
		t.Skip("this host has no root-owned editor to accept")
	}
	link := filepath.Join(t.TempDir(), "ed")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	if got, err := ResolveEditor(link); err != nil || got != good {
		t.Errorf("resolveEditor(%q) = %q, %v; want the resolved %q", link, got, err, good)
	}
}

// Write on a directory is permission to replace what it holds, and write on
// that directory's parent is permission to replace the directory. So a clean
// file in a clean directory is not enough and the walk runs to /.
func TestEveryDirectoryAboveTheEditorIsChecked(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("building a root-owned directory under a loosened one needs root")
	}
	// Not under /tmp: that is 1777 itself, so the walk would stop there and the
	// test would pass without ever reaching the directory it is about.
	//nolint:usetesting // t.TempDir() sits under /tmp, which is the directory
	// this test cannot use.
	base, err := os.MkdirTemp("/root", "faramir-editor-")
	if err != nil {
		t.Skipf("no writable /root on this host: %v", err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(base) })
	mid := filepath.Join(base, "mid")
	if err := os.Mkdir(mid, 0o755); err != nil {
		t.Fatal(err)
	}
	ed := filepath.Join(mid, "ed")
	if err := os.WriteFile(ed, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := ResolveEditor(ed); err != nil {
		t.Fatalf("a root-owned editor in root-owned directories was refused: %v", err)
	}
	// The file and its own directory are untouched; only the one above them is
	// loosened.
	if err := os.Chmod(base, 0o777); err != nil {
		t.Fatal(err)
	}
	err = func() error { _, err := ResolveEditor(ed); return err }()
	if err == nil {
		t.Fatal("accepted an editor two levels under a world-writable directory")
	}
	if !strings.Contains(err.Error(), base) {
		t.Errorf("the refusal does not name %s, so the walk stopped short: %v", base, err)
	}
}
