package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// writeRefuseConfig is an install whose config declares the entries given.
func writeRefuseConfig(t *testing.T, entries string) string {
	t.Helper()
	return configDirWith(t, "[command]\ntimeout_sec = 600\n"+entries)
}

// Every refusal `refuse add` can make before it touches anything. There is no
// grant and no probe to get wrong here, so unlike `link add` these are the only
// ways it declines: the entry is held to what the loader would accept, and the
// path has to be one the install does not already refuse.
func TestAddRefusedRefusesBeforeItChangesAnything(t *testing.T) {
	taken := "[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n"

	for _, tc := range []struct {
		name    string
		entries string
		path    string
		wantErr string
	}{
		{"a relative path", "", "etc/luks.key", "is relative"},
		{"a home", "", "~/.ssh/id_ed25519", "starts with ~"},
		{"no path at all", "", "", "path is required"},
		{"an uncleaned path", "", "/etc/./luks.key", "shortest form"},
		{"the whole filesystem", "", "/", "every file on the host"},
		{"a path already refused", taken, "/etc/luks/volume.key", "already refuses"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeRefuseConfig(t, tc.entries)
			before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
			if err != nil {
				t.Fatal(err)
			}

			_, err = AddRefusedPath(Options{ConfigDir: dir}, config.RefusedPath{Path: tc.path})
			if err == nil {
				t.Fatalf("added %q, want a refusal naming %q", tc.path, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error is %q, want it to name %q", err, tc.wantErr)
			}
			// Refused means nothing was written, not that the write was undone.
			after, err := os.ReadFile(filepath.Join(dir, "config.toml"))
			if err != nil {
				t.Fatal(err)
			}
			if string(after) != string(before) {
				t.Errorf("the config was rewritten by a call that failed:\n%s", after)
			}
		})
	}
}

// The path a caller names is the one the refusal quotes, so an operator can see
// which of several entries was rejected.
func TestAddRefusedNamesThePathItRefused(t *testing.T) {
	dir := writeRefuseConfig(t, "")
	_, err := AddRefusedPath(Options{ConfigDir: dir}, config.RefusedPath{Path: "relative/path"})
	if err == nil {
		t.Fatal("a relative path was accepted")
	}
	if !strings.Contains(err.Error(), "relative/path") {
		t.Errorf("the refusal does not name the path: %v", err)
	}
}

// Removing something the install does not refuse says so, and says where to
// look. Silence would read as a path that had been refused and now is not.
func TestRemoveRefusedOnAPathTheInstallDoesNotRefuse(t *testing.T) {
	dir := writeRefuseConfig(t, "[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n")

	_, _, err := RemoveRefusedPath(Options{ConfigDir: dir}, "/etc/other.key")
	if err == nil {
		t.Fatal("removed a path the config does not name")
	}
	for _, want := range []string{"/etc/other.key", "refuse ls"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error is %q, want it to name %q", err, want)
		}
	}
}

// What `refuse ls` reads. An install that refuses nothing is not an error: it
// is every install until the first entry.
func TestRefusedPathsReadsWhatTheConfigDeclares(t *testing.T) {
	dir := writeRefuseConfig(t, "[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n\n"+
		"[[secret.refuse]]\npath = \"/home/op/.ssh\"\n")

	got, err := RefusedPaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "/etc/luks/volume.key" || got[1].Path != "/home/op/.ssh" {
		t.Fatalf("RefusedPaths = %+v", got)
	}

	empty, err := RefusedPaths(writeRefuseConfig(t, ""))
	if err != nil {
		t.Fatalf("an install that refuses nothing reported an error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("RefusedPaths = %+v, want nothing", empty)
	}
}

// Adoption is what stops a plain `init` from erasing the entries: no flag names
// one, so a run that did not read them back would drop every rule they render.
func TestARerunKeepsTheRefusedPaths(t *testing.T) {
	dir := writeRefuseConfig(t, "[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n")
	opts := Options{ConfigDir: dir}

	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	if len(opts.refused) != 1 || opts.refused[0].Path != "/etc/luks/volume.key" {
		t.Fatalf("adopted %+v, want the entry the config declares", opts.refused)
	}
}

// And a list set deliberately wins over what the file says, empty included, or
// removing the last entry would read as "nothing was named" and adoption would
// put it back.
func TestRemovingTheLastRefusedPathIsNotMistakenForSilence(t *testing.T) {
	dir := writeRefuseConfig(t, "[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n")
	opts := Options{ConfigDir: dir, refused: nil, refusedSet: true}

	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	if len(opts.refused) != 0 {
		t.Errorf("adoption put back %+v after the last entry was removed", opts.refused)
	}
}

// The two entry kinds share one config file and one rewrite of it, so each has
// to survive the other being changed. Both rely on adoption: `refuse add` sets
// only its own list, and a run that did not read the links back would rewrite
// config.toml without them, which takes their values out of the redactor.
func TestChangingOneKindOfEntryKeepsTheOther(t *testing.T) {
	both := "[[secret.link]]\nref = \"gh/token\"\npath = \"/home/op/.config/gh/hosts.yml\"\n" +
		"type = \"yaml\"\nkey = \"token\"\n\n" +
		"[[secret.refuse]]\npath = \"/etc/luks/volume.key\"\n"

	t.Run("refuse add keeps the links", func(t *testing.T) {
		dir := writeRefuseConfig(t, both)
		opts := Options{
			ConfigDir: dir,
			refused: append(refusedAt("/etc/luks/volume.key"),
				config.RefusedPath{Path: "/etc/other.key"}),
			refusedSet: true,
		}
		if _, err := opts.adoptInstalled(); err != nil {
			t.Fatal(err)
		}
		if len(opts.links) != 1 || opts.links[0].Ref != "gh/token" {
			t.Errorf("links = %+v, want the entry the config declares", opts.links)
		}
		if len(opts.refused) != 2 {
			t.Errorf("refused = %+v, want the list the caller set", opts.refused)
		}
	})

	t.Run("link add keeps the refused paths", func(t *testing.T) {
		dir := writeRefuseConfig(t, both)
		opts := Options{
			ConfigDir: dir,
			links: []config.Link{
				{Ref: "gh/token", Path: "/home/op/.config/gh/hosts.yml", Type: "yaml", Key: "token"},
				{Ref: "npm/token", Path: "/home/op/.npmrc", Type: "ini", Key: "_authToken"},
			},
			linksSet: true,
		}
		if _, err := opts.adoptInstalled(); err != nil {
			t.Fatal(err)
		}
		if len(opts.refused) != 1 || opts.refused[0].Path != "/etc/luks/volume.key" {
			t.Errorf("refused = %+v, want the entry the config declares", opts.refused)
		}
		if len(opts.links) != 2 {
			t.Errorf("links = %+v, want the list the caller set", opts.links)
		}
	})
}
