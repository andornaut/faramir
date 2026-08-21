package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// writeBlockConfig is an install whose config declares the entries given.
func writeBlockConfig(t *testing.T, entries string) string {
	t.Helper()
	return configDirWith(t, "[command]\ntimeout_sec = 600\n"+entries)
}

// Every refusal `block add` can make before it touches anything. There is no
// grant and no probe to get wrong here, so unlike `link add` these are the only
// ways it declines: the entry is held to what the loader would accept. A path
// the install already refuses is not among them, an add of one being a request
// for the state that is already there.
func TestAddRefusedRefusesBeforeItChangesAnything(t *testing.T) {
	for _, tc := range []struct {
		name    string
		entries string
		path    string
		wantErr string
	}{
		{"a relative path", "", "etc/luks.key", "is relative"},
		{"a home", "", "~/.ssh/id_ed25519", "starts with ~"},
		{"no path at all", "", "", "path or name is required"},
		{"an uncleaned path", "", "/etc/./luks.key", "shortest form"},
		{"the whole filesystem", "", "/", "every file on the host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := writeBlockConfig(t, tc.entries)
			before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = AddBlockedPath(Options{ConfigDir: dir}, config.BlockedPath{Path: tc.path})
			if err == nil {
				t.Fatalf("added %q, want a refusal naming %q", tc.path, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error is %q, want it to name %q", err, tc.wantErr)
			}
			// Blocked means nothing was written, not that the write was undone.
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
	dir := writeBlockConfig(t, "")
	_, _, err := AddBlockedPath(Options{ConfigDir: dir}, config.BlockedPath{Path: "relative/path"})
	if err == nil {
		t.Fatal("a relative path was accepted")
	}
	if !strings.Contains(err.Error(), "relative/path") {
		t.Errorf("the refusal does not name the path: %v", err)
	}
}

// Which entry set each edit renders, and whether it changed anything. This is
// the whole of what makes the two commands idempotent: a configuration manager
// runs them on every converge, so an add of what is there and a remove of what
// is not have to be the state that is already on the host rather than an error.
func TestTheEntrySetAnAddRenders(t *testing.T) {
	luks := config.BlockedPath{Path: "/etc/luks/volume.key"}
	ssh := config.BlockedPath{Path: "/home/op/.ssh"}

	entries, added := blockedWith([]config.BlockedPath{luks}, ssh)
	if !added {
		t.Error("a path the install does not refuse was not added")
	}
	if len(entries) != 2 || entries[1] != ssh {
		t.Errorf("entries = %+v, want both", entries)
	}

	entries, added = blockedWith([]config.BlockedPath{luks}, luks)
	if added {
		t.Error("a path the install already refuses was added a second time")
	}
	if len(entries) != 1 || entries[0] != luks {
		t.Errorf("entries = %+v, want the one entry unchanged", entries)
	}
}

// Removing a path the install does not refuse writes nothing and reports no
// entry, the caller telling the two apart by that. It is not an error: what was
// asked for is the state the host is in.
func TestRemoveRefusedOnAPathTheInstallDoesNotRefuse(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	before := readConfigFile(t, dir)

	_, removed, err := RemoveBlockedPath(Options{ConfigDir: dir}, config.BlockedPath{Path: "/etc/other.key"})
	if err != nil && strings.Contains(err.Error(), "refuses no path") {
		t.Fatalf("removing a path that is not refused was an error: %v", err)
	}
	if removed.Path != "" {
		t.Errorf("removed = %+v, want nothing", removed)
	}
	if after := readConfigFile(t, dir); after != before {
		t.Errorf("the config was rewritten:\n%s", after)
	}
}

// What `block ls` reads. An install that refuses nothing is not an error: it
// is every install until the first entry.
func TestRefusedPathsReadsWhatTheConfigDeclares(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n\n"+
		"[[secret.block]]\npath = \"/home/op/.ssh\"\n")

	got, err := BlockedPaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "/etc/luks/volume.key" || got[1].Path != "/home/op/.ssh" {
		t.Fatalf("BlockedPaths = %+v", got)
	}

	empty, err := BlockedPaths(writeBlockConfig(t, ""))
	if err != nil {
		t.Fatalf("an install that refuses nothing reported an error: %v", err)
	}
	if len(empty) != 0 {
		t.Errorf("BlockedPaths = %+v, want nothing", empty)
	}
}

// Adoption is what stops a plain `init` from erasing the entries: no flag names
// one, so a run that did not read them back would drop every rule they render.
func TestARerunKeepsTheRefusedPaths(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	opts := Options{ConfigDir: dir}

	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	if len(opts.blocked) != 1 || opts.blocked[0].Path != "/etc/luks/volume.key" {
		t.Fatalf("adopted %+v, want the entry the config declares", opts.blocked)
	}
}

// And a list set deliberately wins over what the file says, empty included, or
// removing the last entry would read as "nothing was named" and adoption would
// put it back.
func TestRemovingTheLastBlockedPathIsNotMistakenForSilence(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	opts := Options{ConfigDir: dir, blocked: nil, blockedSet: true}

	if _, err := opts.adoptInstalled(); err != nil {
		t.Fatal(err)
	}
	if len(opts.blocked) != 0 {
		t.Errorf("adoption put back %+v after the last entry was removed", opts.blocked)
	}
}

// The two entry kinds share one config file and one rewrite of it, so each has
// to survive the other being changed. Both rely on adoption: `block add` sets
// only its own list, and a run that did not read the links back would rewrite
// config.toml without them, which takes their values out of the redactor.
func TestChangingOneKindOfEntryKeepsTheOther(t *testing.T) {
	both := "[[secret.link]]\nref = \"gh/token\"\npath = \"/home/op/.config/gh/hosts.yml\"\n" +
		"type = \"yaml\"\nkey = \"token\"\n\n" +
		"[[secret.block]]\npath = \"/etc/luks/volume.key\"\n"

	t.Run("block add keeps the links", func(t *testing.T) {
		dir := writeBlockConfig(t, both)
		opts := Options{
			ConfigDir: dir,
			blocked: append(refusedAt("/etc/luks/volume.key"),
				config.BlockedPath{Path: "/etc/other.key"}),
			blockedSet: true,
		}
		if _, err := opts.adoptInstalled(); err != nil {
			t.Fatal(err)
		}
		if len(opts.links) != 1 || opts.links[0].Ref != "gh/token" {
			t.Errorf("links = %+v, want the entry the config declares", opts.links)
		}
		if len(opts.blocked) != 2 {
			t.Errorf("refused = %+v, want the list the caller set", opts.blocked)
		}
	})

	t.Run("link add keeps the blocked paths", func(t *testing.T) {
		dir := writeBlockConfig(t, both)
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
		if len(opts.blocked) != 1 || opts.blocked[0].Path != "/etc/luks/volume.key" {
			t.Errorf("refused = %+v, want the entry the config declares", opts.blocked)
		}
		if len(opts.links) != 2 {
			t.Errorf("links = %+v, want the list the caller set", opts.links)
		}
	})
}
