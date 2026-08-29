package install

import (
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// Nothing is compiled in, so a path outside this install's own directories is
// removable whatever it is: a check that refused one of these would be refusing
// on grounds that no longer exist.
func TestOnlyTheLayoutBlocksWithoutAnEntry(t *testing.T) {
	dir := writeBlockConfig(t, "")
	for _, asked := range []config.BlockedPath{
		{Path: "/home/op/.config/sops/age/keys.txt"},
		{Path: "/home/op/.ssh/id_rsa"},
		{Path: "/mnt/vol/luks.key"},
	} {
		if err := BuiltInRuleError(dir, asked); err != nil {
			t.Errorf("%s: removal was refused with nothing to refuse it: %v",
				asked.Blocks(), err)
		}
	}
}

// The install's own directories are the rules an entry cannot take back: they
// come out of the layout on every render. Reporting "nothing removed" for one
// would read as the file becoming readable.
func TestRemovingAPathTheLayoutBlocksIsRefused(t *testing.T) {
	dir := writeBlockConfig(t, "")
	for _, asked := range []config.BlockedPath{
		{Path: dir},
		{Path: filepath.Join(dir, "age.key")},
		{Path: filepath.Join(dir, "secrets", "db.sops.yml")},
		{Path: "/var/log/faramir/audit.log"},
	} {
		err := BuiltInRuleError(dir, asked)
		if err == nil {
			t.Errorf("%s: removing a path the layout blocks was allowed, which "+
				"reports it as no longer blocked", asked.Blocks())
			continue
		}
		if !strings.Contains(err.Error(), "block ls") {
			t.Errorf("%s: the refusal does not say where to look: %v", asked.Blocks(), err)
		}
	}
}

// A neighbour whose name merely starts the same way is not under it.
func TestASiblingOfAnInstalledDirectoryIsRemovable(t *testing.T) {
	dir := writeBlockConfig(t, "")
	if err := BuiltInRuleError(dir, config.BlockedPath{Path: dir + "-notes"}); err != nil {
		t.Errorf("%s-notes was read as being under %s: %v", dir, dir, err)
	}
}

// A declared entry is removable, which is what the check above must not get in
// the way of.
func TestADeclaredEntryIsRemovable(t *testing.T) {
	dir := writeBlockConfig(t, "[[secret.block]]\npath = \"/home/op/age.key\"\n")
	if err := BuiltInRuleError(dir, config.BlockedPath{Path: "/home/op/age.key"}); err != nil {
		t.Errorf("a declared entry was refused: %v", err)
	}
}

// A path and a command are separate entries: they render different rules, so
// one must not stand in for the other on add or on rm.
func TestAPathAndACommandAreNotOneEntry(t *testing.T) {
	path := config.BlockedPath{Path: "/etc/luks/volume.key"}
	command := config.BlockedPath{Command: "op read"}
	if sameBlock(path, command) {
		t.Error("a path and a command were read as one entry")
	}
	entries, added := blockedWith([]config.BlockedPath{path}, command)
	if !added || len(entries) != 2 {
		t.Errorf("adding a command beside a path gave %d entry(ies), added=%v", len(entries), added)
	}
	if _, again := blockedWith(entries, command); again {
		t.Error("the same command was added twice")
	}
}

// A dozen paths in one command, which is what a first run pastes and what a
// converge hands over. What the fold has to get right is which entries were new
// and what the resulting set is; that it costs one write rather than a dozen is
// the caller applying it once, which the e2e suite exercises on a real host.
func TestSeveralEntriesFoldIntoOneSet(t *testing.T) {
	existing := []config.BlockedPath{{Path: "/mnt/vol/luks.key"}}
	asked := []config.BlockedPath{
		{Path: "/home/op/.ssh"},
		{Path: "/mnt/vol/luks.key"}, // already there
		{Command: "op read"},
		{Path: "/etc/wpa.conf"},
		{Path: "/home/op/.ssh"}, // named twice in one call
	}
	entries, added := foldBlocked(existing, asked)
	if want := []bool{true, false, true, true, false}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v: an entry already there, and one named twice "+
			"in one call, are both reported as not added", added, want)
	}
	// Order kept, and the entry already there is not moved by the ones added
	// beside it.
	want := []string{"/mnt/vol/luks.key", "/home/op/.ssh", "op read", "/etc/wpa.conf"}
	if len(entries) != len(want) {
		t.Fatalf("the set holds %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for i, refuses := range want {
		if got := entries[i].Blocks(); got != refuses {
			t.Errorf("entry %d is %q, want %q", i, got, refuses)
		}
	}
	// The one it started with is untouched by a fold that added nothing.
	if _, added := foldBlocked(entries, []config.BlockedPath{{Path: "/mnt/vol/luks.key"}}); added[0] {
		t.Error("an entry already in the set was reported as added")
	}
}

// One bad entry writes none of the list. A partial write would leave the
// operator to work out which half of what they pasted took.
func TestOneBadEntryWritesNoneOfTheList(t *testing.T) {
	dir := writeBlockConfig(t, "")
	before, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = AddBlockedPaths(Options{ConfigDir: dir}, []config.BlockedPath{
		{Path: "/home/op/.ssh"},
		{Path: "relative/not/absolute"}, // refused: a path entry is absolute
		{Path: "/etc/wpa.conf"},
	})
	if err == nil {
		t.Fatal("a list carrying an entry that cannot be written was accepted")
	}
	after, err := os.ReadFile(filepath.Join(dir, "config.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Errorf("a refused list wrote part of itself:\n%s", after)
	}
}

// A declared path reached through a variable, in the spellings a shell accepts.
// The read rules need a command before the path; a binding names it with none
// near it, so the binding is what refuses it.
//
// The quoted forms matter because a declared path may carry a space: "Local
// Storage" is one, and a rule that ended the value at the first space would
// never see the half that matters.
func TestADeclaredPathIsRefusedWhenBoundToAVariable(t *testing.T) {
	layout := Layout{ConfigDir: "/etc/faramir", Blocked: []config.BlockedPath{
		{Path: "/srv/secrets.yml"},
		{Path: "/home/op/.ssh/id_rsa"},
		{Path: "/home/op/.config/chromium/Default/Local Storage"},
	}}
	rules := commandRules(layout)
	res := make([]*regexp.Regexp, 0, len(rules))
	for _, rule := range rules {
		res = append(res, regexp.MustCompile("(?i)"+rule))
	}
	matches := func(cmd string) bool {
		for _, re := range res {
			if re.MatchString(cmd) {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{
		`p=/srv/secrets.yml`,
		`p="/srv/secrets.yml"`,
		`p='/srv/secrets.yml'`,
		`export KEY="/home/op/.ssh/id_rsa"`,
		`p="/home/op/.config/chromium/Default/Local Storage"`,
		`for d in /srv; do cat /srv/secrets.yml; done`,
		// Anywhere inside the quotes, not only where the value opens: the value
		// is bounded by the quote rather than by the first space.
		`p="see /srv/secrets.yml for it"`,
	} {
		if !matches(cmd) {
			t.Errorf("%q is allowed, and it names a declared file", cmd)
		}
	}
	// A quoted value that opens with something other than a path character is
	// prose. Refusing a sentence for holding a word out of a declared path costs
	// an operator a refusal they cannot act on.
	for _, cmd := range []string{
		`echo "my secrets talk"`,
		`git commit -m "rotate the secrets"`,
		`title="my writing about ordinary things"`,
		`msg=hello secrets`,
		`title="my secrets talk"`,
		`msg='the secrets are safe'`,
	} {
		if matches(cmd) {
			t.Errorf("%q is refused, and it reaches no declared file", cmd)
		}
	}
}
