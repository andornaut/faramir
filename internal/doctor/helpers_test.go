package doctor

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/layouttest"
)

// pinSudo answers the sudo-flavour probe for the duration of one test, so both
// arrangements are diagnosed on whichever sudo this machine happens to have.
func pinSudo(t *testing.T, rs bool) {
	t.Helper()
	original := hostsudo.RsProbe
	hostsudo.RsProbe = func() bool { return rs }
	t.Cleanup(func() { hostsudo.RsProbe = original })
}

// writeBlockConfig is an install whose config declares the entries given.
func writeBlockConfig(t *testing.T, entries string) string {
	t.Helper()
	return configDirWith(t, "[command]\ntimeout_sec = 600\n"+entries)
}

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

// testLayout is the install a diagnosis re-renders against. The shared fixture
// rather than one built through Options: what these tests compare is a render
// against a file, and going through the installer to get a layout would put its
// defaults into the comparison.
func testLayout() hostlayout.Layout { return layouttest.Layout() }
