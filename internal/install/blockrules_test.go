package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
)

// Rendering is what actually refuses the read, so being in the returned list is
// not enough.
func TestARefusedPathReachesTheRenderedAccountFiles(t *testing.T) {
	layout := testLayout()
	layout.Blocked = refusedAt("/etc/luks/volume.key")

	for _, asset := range []string{"agent/claude/settings.json", "agent/permissions.json.tmpl"} {
		body, err := agentcfg.RenderAccount(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if !strings.Contains(string(body), "/etc/luks/volume.key") {
			t.Errorf("%s does not refuse the path", asset)
		}
	}
}

// The round trip that makes config.toml the entries' home: init renders them
// into the file it rewrites every run and reads them back on the next. Either
// half alone would erase them, and erasing them drops the deny rules.
//
// Every form, because the template writes one branch per form and a form with
// no branch is written as another form's empty key: the command branch was
// missing, so `block add --command` rendered `path = ""` and produced a config
// that would not load. A test that wrote its own TOML said the loader reads
// the key, which was true and was not the question.
func TestEveryBlockedFormRoundTripsThroughTheRenderedConfig(t *testing.T) {
	layout := testLayout()
	layout.Blocked = []config.BlockedPath{
		{Path: "/etc/luks/volume.key"},
		{Path: "/home/operator/.ssh"},
		{Command: "op read"},
		{Command: "sops -d"},
	}

	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	// It has to load as a whole, not merely contain the right text: an entry
	// rendered in the wrong place is a config no daemon can read.
	if _, err := config.Load(path); err != nil {
		t.Fatalf("the rendered config does not load: %v\n%s", err, body)
	}
	back, err := config.BaseBlocked(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(back) != len(layout.Blocked) {
		t.Fatalf("read back %d entries, want %d:\n%s", len(back), len(layout.Blocked), body)
	}
	for i, want := range layout.Blocked {
		if back[i] != want {
			t.Errorf("entry %d read back as %+v, want %+v", i, back[i], want)
		}
	}
}

// -- the doctor check -------------------------------------------------------

// perInstallPaths is the entries and nothing else. The install's own
// directories are rendered beside it as subtree rules, so adding them here
// writes a second, differently shaped rule for each of them into every agent's
// file, and nothing downstream compares the set it was given.
func TestPerInstallPathsIsTheEntriesAlone(t *testing.T) {
	layout := testLayout()
	layout.Links = linksAt("/etc/luks/volume.key")
	layout.Blocked = refusedAt("/srv/keys/api.pem", "/etc/luks/volume.key")

	want := []string{"/etc/luks/volume.key", "/srv/keys/api.pem"}
	if got := agentcfg.PerInstallPaths(layout); !slices.Equal(got, want) {
		t.Errorf("perInstallPaths = %v, want the entries sorted and deduplicated "+
			"across the two forms: %v", got, want)
	}
}
