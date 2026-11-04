package install

// An entry edit under DryRun: what `block` and `link` take --dry-run for.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// entryEditable lets a whole entry edit run in a test: the layout accepts a
// config directory under the test's temporary one, which it otherwise refuses
// as PrivateTmp's, and preflight finds the binaries it looks for beside the
// running one, here the test binary.
func entryEditable(t *testing.T) {
	t.Helper()
	was := hostlayout.PrivateTmp
	hostlayout.PrivateTmp = nil
	t.Cleanup(func() { hostlayout.PrivateTmp = was })
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range installedBinaries {
		stub := filepath.Join(filepath.Dir(self), name)
		if _, err := os.Stat(stub); err == nil {
			continue
		}
		if err := os.WriteFile(stub, nil, 0o700); err != nil {
			t.Skipf("no binary beside the test binary for preflight to find: %v", err)
		}
		t.Cleanup(func() { _ = os.Remove(stub) })
	}
}

// dirContents is every entry in dir and what each file holds, so a run that
// wrote anything there, a new file or directory included, compares unequal.
// One level: an install directory written by these tests has no other.
func dirContents(t *testing.T, dir string) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]string{}
	for _, entry := range entries {
		if entry.IsDir() {
			out[entry.Name()+"/"] = ""
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		out[entry.Name()] = string(body)
	}
	return out
}

// sameContents compares two dirContents results.
func sameContents(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for path, body := range a {
		if other, ok := b[path]; !ok || other != body {
			return false
		}
	}
	return true
}

// A dry run answers the question a configuration manager's check mode asks,
// would this change the host, and writes nothing to find out: an entry the
// config does not carry is reported as a change, and the config is as it was.
func TestADryRunBlockEditReportsTheChangeAndWritesNothing(t *testing.T) {
	const declared = "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n"
	for _, tc := range []struct {
		name  string
		entry string
		edit  func(Options) (Report, error)
	}{
		{"add", "", func(opts Options) (Report, error) {
			report, added, err := AddBlockedPaths(opts,
				[]config.BlockedPath{{Path: "/etc/luks/volume.key"}})
			if err == nil && !slices.Equal(added, []bool{true}) {
				t.Errorf("added = %v, want the entry reported new", added)
			}
			return report, err
		}},
		{"rm", declared, func(opts Options) (Report, error) {
			report, removed, err := RemoveBlockedPaths(opts,
				[]config.BlockedPath{{Path: "/etc/luks/volume.key"}})
			if err == nil && (len(removed) != 1 || removed[0].Path != "/etc/luks/volume.key") {
				t.Errorf("removed = %+v, want the declared entry", removed)
			}
			return report, err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			entryEditable(t)
			dir := layouttest.BlockConfigDir(t, tc.entry)
			before := dirContents(t, dir)

			report, err := tc.edit(Options{ConfigDir: dir, AgentUser: currentUserName(t), DryRun: true})
			if err != nil {
				t.Fatal(err)
			}

			if !report.DryRun || !report.Changed {
				t.Errorf("dry_run = %v, changed = %v, want both true", report.DryRun, report.Changed)
			}
			if !sameContents(before, dirContents(t, dir)) {
				t.Error("a dry run wrote into the install directory")
			}
		})
	}
}

// The same for a link, through rm: add asks the broker's account to read the
// file, which a test cannot be.
func TestADryRunLinkRemovalReportsTheChangeAndWritesNothing(t *testing.T) {
	entryEditable(t)
	present := filepath.Join(t.TempDir(), "hosts.yml")
	if err := os.WriteFile(present, []byte("token: a-long-secret-value\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := writeLinkConfig(t, "[[secret.link]]\nref = \"gh/token\"\npath = \""+present+"\"\n"+
		"type = \"yaml\"\nkey = \"token\"\n")
	before := dirContents(t, dir)

	report, removed, err := RemoveLink(Options{ConfigDir: dir, AgentUser: currentUserName(t),
		DryRun: true}, "gh/token")
	if err != nil {
		t.Fatal(err)
	}

	if removed.Ref != "gh/token" {
		t.Errorf("removed = %+v, want the declared entry", removed)
	}
	if !report.DryRun || !report.Changed {
		t.Errorf("dry_run = %v, changed = %v, want both true", report.DryRun, report.Changed)
	}
	if !sameContents(before, dirContents(t, dir)) {
		t.Error("a dry run wrote into the install directory")
	}
}
