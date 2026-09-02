package layouttest

// Install directories built from a config body, for the tests that hand a
// command a directory and let it join the file name on.

import (
	"os"
	"path/filepath"
	"testing"
)

// ConfigDir is an install directory holding this config.toml.
func ConfigDir(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil { //nolint:gosec // G306: the mode the install writes config.toml with
		t.Fatal(err)
	}
	return dir
}

// BlockConfigDir is an install whose config declares the entries given.
func BlockConfigDir(t *testing.T, entries string) string {
	t.Helper()
	return ConfigDir(t, "[command]\ntimeout_sec = 600\n"+entries)
}

// Touch writes an empty JSON object at rel under home, creating the
// directories above it: the mark that says an agent is in use there.
func Touch(t *testing.T, home, rel string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}
