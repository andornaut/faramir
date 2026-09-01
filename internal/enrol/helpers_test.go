package enrol

import (
	"os"
	"path/filepath"
	"testing"
)

// configDirWith is an install directory holding this config.toml, for the
// commands that take a directory and join the file name onto it.
func configDirWith(t *testing.T, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}
