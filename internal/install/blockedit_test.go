package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/layouttest"
)

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
		{"no path at all", "", "", "path or command is required"},
		{"an uncleaned path", "", "/etc/./luks.key", "shortest form"},
		{"the whole filesystem", "", "/", "every file on the host"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := layouttest.BlockConfigDir(t, tc.entries)
			before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
			if err != nil {
				t.Fatal(err)
			}

			_, _, err = AddBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{{Path: tc.path}})
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
	dir := layouttest.BlockConfigDir(t, "")
	_, _, err := AddBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{{Path: "relative/path"}})
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
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	before := readConfigFile(t, dir)

	_, removed, err := RemoveBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{{Path: "/etc/other.key"}})
	if err != nil && strings.Contains(err.Error(), "refuses no path") {
		t.Fatalf("removing a path that is not refused was an error: %v", err)
	}
	for _, entry := range removed {
		if entry.Path != "" {
			t.Errorf("removed = %+v, want nothing", removed)
		}
	}
	if after := readConfigFile(t, dir); after != before {
		t.Errorf("the config was rewritten:\n%s", after)
	}
}

// What `block ls` reads. An install that refuses nothing is not an error: it
// is every install until the first entry.
func TestRefusedPathsReadsWhatTheConfigDeclares(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n\n"+
		"[[secret.block]]\npath = \"/home/op/.ssh\"\n")

	got, err := BlockedPaths(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Path != "/etc/luks/volume.key" || got[1].Path != "/home/op/.ssh" {
		t.Fatalf("BlockedPaths = %+v", got)
	}

	empty, err := BlockedPaths(layouttest.BlockConfigDir(t, ""))
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
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
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
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
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
		dir := layouttest.BlockConfigDir(t, both)
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
		dir := layouttest.BlockConfigDir(t, both)
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

// A list is what a first run pastes and what a converge hands over, so one bad
// entry in it has to leave the host as it was rather than writing the entries
// that came before it. Every entry is held to the loader's rules before
// anything is written, which is the only reason that holds.
func TestABatchCarryingOneBadEntryWritesNoneOfIt(t *testing.T) {
	good := config.BlockedPath{Path: "/etc/luks/volume.key"}
	for _, tc := range []struct {
		name string
		bad  config.BlockedPath
	}{
		{"a path carrying a newline", config.BlockedPath{Path: "/etc/aaa\nbbb"}},
		{"a relative path", config.BlockedPath{Path: "etc/luks.key"}},
		{"the whole filesystem", config.BlockedPath{Path: "/"}},
		{"an entry naming nothing", config.BlockedPath{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := layouttest.BlockConfigDir(t, "")
			before := readConfigFile(t, dir)

			_, added, err := AddBlockedPaths(Options{ConfigDir: dir},
				[]config.BlockedPath{good, tc.bad})
			if err == nil {
				t.Fatal("the batch was accepted")
			}
			if len(added) != 0 {
				t.Errorf("added = %v, want nothing reported added", added)
			}
			if got := readConfigFile(t, dir); got != before {
				t.Errorf("the good entry was written by a batch that failed:\n%s", got)
			}
		})
	}
}

// Folding one entry at a time against what the last one left is what makes a
// list behave like the same commands run in that order: the second naming of
// an entry is already there rather than a second rule saying the same thing.
func TestABatchNamingOneEntryTwiceAddsItOnce(t *testing.T) {
	luks := config.BlockedPath{Path: "/etc/luks/volume.key"}
	ssh := config.BlockedPath{Path: "/home/op/.ssh"}

	entries, added := foldBlocked(nil, []config.BlockedPath{luks, ssh, luks})
	if len(entries) != 2 {
		t.Errorf("entries = %+v, want the two distinct ones", entries)
	}
	if want := []bool{true, true, false}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}

	// And against what the install already carries, not only within the list.
	entries, added = foldBlocked([]config.BlockedPath{luks}, []config.BlockedPath{luks, ssh})
	if len(entries) != 2 {
		t.Errorf("entries = %+v, want the existing one and the new one", entries)
	}
	if want := []bool{false, true}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
}

// The form is part of what an entry says. A path and a command spelled the same
// render different rules, so neither stands in for the other and an add of the
// second is not an add of what is already there.
func TestAnEntryIsTheSameOnlyWhenItsFormIsTheSame(t *testing.T) {
	const spelling = "/etc/luks/volume.key"
	path := config.BlockedPath{Path: spelling}
	command := config.BlockedPath{Command: spelling}
	if sameBlock(path, command) {
		t.Error("a path and a command spelled alike are read as one entry")
	}
	entries, added := blockedWith([]config.BlockedPath{path}, command)
	if !added || len(entries) != 2 {
		t.Errorf("added = %v, entries = %+v, want the command added beside the path",
			added, entries)
	}
}

// What an add says about the entry it wrote, one warning per form. A path is
// the only form asked of the filesystem: a name and a command are matched
// against what an agent writes, so neither reaches a file to be missing.
func TestEachFormOfEntryIsWarnedAboutOnItsOwnTerms(t *testing.T) {
	const linked = "/etc/linked.key"
	links := []config.Link{{Path: linked, Ref: "some/ref"}}
	for _, tc := range []struct {
		name  string
		entry config.BlockedPath
		want  []string
		gone  []string
	}{
		{
			name:  "a command names what it will and will not catch",
			entry: config.BlockedPath{Command: "sops"},
			want:  []string{"sops", "literal", "where a command starts", "is left alone"},
			gone:  []string{"is not there"},
		},
		{
			name:  "a path that is not there is said, an unmounted volume looking so",
			entry: config.BlockedPath{Path: "/nowhere/absent.key"},
			want:  []string{"/nowhere/absent.key", "is not there"},
		},
		{
			name:  "a path a link already refuses adds nothing to it",
			entry: config.BlockedPath{Path: linked},
			want:  []string{linked, "some/ref", "adds nothing"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var report Report
			blockedWarnings(&report, tc.entry, links)
			joined := strings.Join(report.Warnings, "\n")
			for _, want := range tc.want {
				if !strings.Contains(joined, want) {
					t.Errorf("the warnings do not say %q:\n%s", want, joined)
				}
			}
			for _, gone := range tc.gone {
				if strings.Contains(joined, gone) {
					t.Errorf("the warnings say %q, which is about a path:\n%s", gone, joined)
				}
			}
		})
	}
}

// An entry naming the tree the agent works in, or a directory holding one. The
// rule is rendered into that tree's own settings file, so the agent is refused
// every file in the directory it was pointed at, by a rule it can read and
// cannot lift. Nothing in such an entry is a secret: the file inside worth
// refusing can be named on its own.
func TestAddRefusedWillNotBlockAnEnrolledTree(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "")
	home := t.TempDir()
	tree := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := agentcfg.RecordEnrolment(dir, agentcfg.EnrolledTree{
		Dir: tree, AgentUser: "op", Agents: []string{"claude"},
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, path, wantErr string }{
		{"the tree itself", tree, "is an enrolled tree"},
		{"the home above it", home, "holds the enrolled tree"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := AddBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{{Path: tc.path}})
			if err == nil {
				t.Fatalf("blocked %q", tc.path)
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error is %q, want it to say %q", err, tc.wantErr)
			}
			if !strings.Contains(err.Error(), tree) {
				t.Errorf("error is %q, want it to name the tree", err)
			}
		})
	}

	// And what is inside a tree, or merely beside it, is the ordinary entry.
	for _, path := range []string{
		filepath.Join(tree, ".env"),
		filepath.Join(tree, "sub"),
		tree + "2",
	} {
		if err := refuseEnrolledTrees(dir, []string{path}); err != nil {
			t.Errorf("%s was refused: %v", path, err)
		}
	}
	// A command names no path, so it is never asked about: the tree rule is
	// about a path rendered over a tree, and a command entry renders none.
	if got := blockedPathsOf([]config.BlockedPath{
		{Command: "op read"},
		{Path: "/srv/luks.key"},
	}); len(got) != 1 || got[0] != "/srv/luks.key" {
		t.Errorf("the paths of a mixed set are %v, want the one path", got)
	}
}
