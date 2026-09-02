package keeper

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// One rule for globs and literal paths alike: an entry naming nothing is an
// error.
func TestResolveExpandsPatternsAndLiterals(t *testing.T) {
	dir := t.TempDir()
	for _, name := range []string{"a.sops.yml", "b.sops.yml", "notes.txt"} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	glob := filepath.Join(dir, "*.sops.yml")
	literal := filepath.Join(dir, "a.sops.yml")
	missing := filepath.Join(dir, "gone.sops.yml")

	for _, tc := range []struct {
		name           string
		entries        []string
		wantPaths      []string
		wantErrs       int
		wantUnresolved int
	}{
		{"a pattern", []string{glob},
			[]string{filepath.Join(dir, "a.sops.yml"), filepath.Join(dir, "b.sops.yml")}, 0, 0},
		{"a literal", []string{literal}, []string{literal}, 0, 0},
		// Decrypting twice would report every ref in it as doubly defined.
		{"a pattern and a literal inside it", []string{glob, literal},
			[]string{filepath.Join(dir, "a.sops.yml"), filepath.Join(dir, "b.sops.yml")}, 0, 0},
		// Named nothing rather than failed: a store not written yet is what every
		// first install looks like. What makes it safe is that the value set is
		// then empty, and exec and redact are refused while it is.
		{"a literal that is not there", []string{missing}, []string{}, 0, 1},
		{"a pattern that matches nothing",
			[]string{filepath.Join(dir, "*.sops.yaml")}, []string{}, 0, 1},
		{"a directory that is not there",
			[]string{filepath.Join(dir, "absent", "*.sops.yml")}, []string{}, 0, 1},
		{"nothing configured", nil, []string{}, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			paths, errs, unresolvedEntries := Resolve(tc.entries)
			if len(paths) != len(tc.wantPaths) {
				t.Fatalf("paths = %v, want %v", paths, tc.wantPaths)
			}
			for i, want := range tc.wantPaths {
				if paths[i] != want {
					t.Errorf("paths[%d] = %q, want %q", i, paths[i], want)
				}
			}
			if len(errs) != tc.wantErrs {
				t.Errorf("errors = %v, want %d", errs, tc.wantErrs)
			}
			if len(unresolvedEntries) != tc.wantUnresolved {
				t.Errorf("unresolved = %v, want %d", unresolvedEntries, tc.wantUnresolved)
			}
		})
	}
}

// Reported apart from the errors, an entry naming nothing being what a first
// install looks like. The broker starts on it and refuses exec and redact
// while the value set is empty, and `--check` and `doctor` fail on it.
func TestAPatternThatNamesNothingIsReportedAsUnresolved(t *testing.T) {
	pattern := filepath.Join(t.TempDir(), "*.sops.yml")
	k := &Keeper{
		config: &config.Config{Secret: config.SecretConfig{Patterns: []string{pattern}}},
		Keys:   newKeyHolder(config.KeeperConfig{}),
	}

	resp := handle(k, map[string]any{"op": "get_state"})
	if state := states(t, resp); len(state) != 0 {
		t.Errorf("state = %v, want empty", state)
	}
	if errs := errorsIn(t, resp); len(errs) != 0 {
		t.Errorf("errors = %v, want none: naming nothing is not a load failure", errs)
	}
	absent := unresolved(t, resp)
	if len(absent) != 1 || !strings.Contains(absent[0], "matched no files") {
		t.Errorf("unresolved = %v, want one saying the pattern matched no files", absent)
	}
}

// Picked up with nothing edited and no daemon restarted, which is why the
// expansion happens per request.
func TestAFileAddedToTheStoreIsPickedUp(t *testing.T) {
	dir := t.TempDir()
	first := filepath.Join(dir, "a.sops.yml")
	if err := os.WriteFile(first, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	k := &Keeper{
		config: &config.Config{Secret: config.SecretConfig{
			Patterns: []string{filepath.Join(dir, "*.sops.yml")},
		}},
		Keys: newKeyHolder(config.KeeperConfig{}),
	}

	if state := states(t, handle(k, map[string]any{"op": "get_state"})); len(state) != 1 {
		t.Fatalf("state = %v, want the one file", state)
	}
	if err := os.WriteFile(filepath.Join(dir, "b.sops.yml"), []byte("y"), 0o600); err != nil {
		t.Fatal(err)
	}
	state := states(t, handle(k, map[string]any{"op": "get_state"}))
	if len(state) != 2 {
		t.Errorf("state = %v, want both files without a reload of the config", state)
	}
}

// The store is one directory spelled once per extension a managed file may
// carry, so two of the three matching nothing is the ordinary case rather than
// a store two thirds missing. Reporting it would fail --check and doctor on
// every host that keeps only *.sops.yml, which is every host.
func TestUnmatchedExtensionsAreNotAMissingStore(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.sops.yml"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	paths, errs, unresolved := Resolve([]string{
		filepath.Join(dir, "*.sops.yml"),
		filepath.Join(dir, "*.sops.yaml"),
		filepath.Join(dir, "*.sops.json"),
	})
	if len(paths) != 1 {
		t.Fatalf("paths = %v, want the one file", paths)
	}
	if len(errs) != 0 || len(unresolved) != 0 {
		t.Errorf("errors = %v, unresolved = %v, want neither", errs, unresolved)
	}
}

// A store that matched nothing at all is still reported: that is a broker
// redacting nothing, and it has to be told from files not written yet.
func TestAStoreThatMatchedNothingIsStillReported(t *testing.T) {
	dir := t.TempDir()
	_, _, unresolved := Resolve([]string{filepath.Join(dir, "*.sops.yml")})
	if len(unresolved) != 1 {
		t.Errorf("unresolved = %v, want the entry that named nothing", unresolved)
	}
}

// A pattern that matched nothing says which nothing it was. Glob returns no
// matches and no error whether the directory holds no file or this process
// cannot read it, and the default install names a pattern, so the flat answer
// is the one every host would get: an operator reads "matched no files" and
// goes to write one, when the store is there and the keeper has lost the
// directory.
func TestAPatternSaysWhetherItCouldReadTheDirectoryAtAll(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads a directory whatever its mode")
	}
	dir := t.TempDir()

	// Nothing written yet.
	_, _, empty := Resolve([]string{filepath.Join(dir, "*.sops.yml")})
	if len(empty) != 1 || !strings.Contains(empty[0], "matched no files") {
		t.Fatalf("unresolved = %v, want it to say the directory holds no match", empty)
	}

	// The same directory, unreadable.
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	_, _, refused := Resolve([]string{filepath.Join(dir, "*.sops.yml")})
	if len(refused) != 1 {
		t.Fatalf("unresolved = %v, want the entry that named nothing", refused)
	}
	if strings.Contains(refused[0], "matched no files") {
		t.Errorf("unresolved = %q, which reads as an empty directory", refused[0])
	}
	if !strings.Contains(refused[0], dir) || !strings.Contains(refused[0], "cannot read") {
		t.Errorf("unresolved = %q, want it to name the directory it could not read", refused[0])
	}

	// And a directory that is not there at all is neither of those.
	missing := filepath.Join(dir, "gone")
	_, _, absent := Resolve([]string{filepath.Join(missing, "*.sops.yml")})
	if len(absent) != 1 || strings.Contains(absent[0], "matched no files") {
		t.Errorf("unresolved = %v, want it to say the directory is not there", absent)
	}
}
