package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/layouttest"
)

// A link names the file that holds the value, because that is the file whose
// group is changed and the file the broker is granted. The name the operator
// typed is the one their agent has, so it becomes a rule of its own rather than
// a refusal telling them to type the other one.

func TestALinkedSymlinkDerivesTheSpellingThatWasTyped(t *testing.T) {
	link, target := linkedFile(t)
	dir := layouttest.BlockConfigDir(t, "")

	opts, derived, err := withLinkDerivation(Options{ConfigDir: dir}, dir, link,
		config.Link{Ref: "npm/token", Path: target, Type: "text", Strict: true})

	if err != nil {
		t.Fatal(err)
	}
	if !derived.written {
		t.Fatalf("derived = %+v, want the typed spelling written", derived)
	}
	if derived.entry.Path != link {
		t.Errorf("path = %q, want the spelling that was typed, %q", derived.entry.Path, link)
	}
	if derived.entry.DerivedFrom != target {
		t.Errorf("derived_from = %q, want the entry's own path %q",
			derived.entry.DerivedFrom, target)
	}
	// The strictness of the entry it stands in for: one flag, one meaning, on
	// whichever entry names the file.
	if !derived.entry.Strict {
		t.Error("the derived entry is not strict, and the link is")
	}
	if !opts.blockedSet {
		t.Fatal("the entry was not folded into what the add renders")
	}
	if len(opts.blocked) != 1 || opts.blocked[0].Path != link {
		t.Errorf("blocked = %+v, want the derived entry", opts.blocked)
	}
}

// A path that names the file directly derives nothing, and leaves the blocked
// list alone: options that said "these are the entries" with a list built here
// would drop whatever the config carried.
func TestALinkNamingTheFileDerivesNothing(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "")
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(base, "npmrc")
	if err := os.WriteFile(path, []byte("//registry:_authToken=x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	opts, derived, err := withLinkDerivation(Options{ConfigDir: dir}, dir, path,
		config.Link{Ref: "npm/token", Path: path, Type: "text"})

	if err != nil {
		t.Fatal(err)
	}
	if derived.entry.Path != "" || derived.written {
		t.Errorf("derived = %+v, want nothing", derived)
	}
	if opts.blockedSet {
		t.Error("the blocked list was replaced by an add that derived nothing")
	}
}

// The typed spelling is not blocked where a rule for it would refuse the agent
// the tree it works in. Said rather than passed over: the file is reachable
// under that name, and an operator must not be left assuming otherwise.
func TestATypedSpellingInsideAnEnrolledTreeIsNotDerived(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "")
	tree, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := agentcfg.RecordEnrolment(dir,
		agentcfg.EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}

	opts, derived, err := withLinkDerivation(Options{ConfigDir: dir}, dir, tree,
		config.Link{Ref: "npm/token", Path: filepath.Join(tree, "npmrc"), Type: "text"})

	if err != nil {
		t.Fatal(err)
	}
	if derived.written {
		t.Error("an entry was written over an enrolled tree")
	}
	if opts.blockedSet {
		t.Error("the blocked list was rewritten by a derivation that was declined")
	}
	var report Report
	derived.say(&report, tree, config.Link{Ref: "npm/token", Path: filepath.Join(tree, "npmrc")})
	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "not blocked") {
		t.Errorf("warnings = %q, want one saying the spelling is still open", report.Warnings)
	}
}

// The entry was written because the link reached the file under that name, so
// it goes when the link does.
func TestRemovingALinkTakesTheSpellingItDerived(t *testing.T) {
	target := "/home/op/dotfiles/npmrc"
	typed := "/home/op/.npmrc"
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \""+typed+"\"\n"+
		"derived_from = \""+target+"\"\n\n[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	configFile := filepath.Join(dir, "config.toml")

	opts, cascaded, err := withoutLinkDerivation(Options{ConfigDir: dir}, configFile,
		config.Link{Ref: "npm/token", Path: target, Type: "text"})

	if err != nil {
		t.Fatal(err)
	}
	if cascaded.Path != typed {
		t.Errorf("cascaded = %+v, want the derived entry", cascaded)
	}
	if !opts.blockedSet {
		t.Fatal("the removal did not rewrite the blocked list")
	}
	if len(opts.blocked) != 1 || opts.blocked[0].Path != "/etc/luks/volume.key" {
		t.Errorf("blocked = %+v, want the unrelated entry alone", opts.blocked)
	}
}

// A ref this install does not carry removes nothing, and a link that derived
// nothing leaves the list as it was.
func TestRemovingALinkThatDerivedNothingRewritesNothing(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \"/etc/luks/volume.key\"\n")
	configFile := filepath.Join(dir, "config.toml")

	for _, removed := range []config.Link{
		{},
		{Ref: "npm/token", Path: "/home/op/dotfiles/npmrc", Type: "text"},
	} {
		opts, cascaded, err := withoutLinkDerivation(Options{ConfigDir: dir}, configFile, removed)
		if err != nil {
			t.Fatal(err)
		}
		if cascaded.Path != "" {
			t.Errorf("cascaded = %+v for %+v, want nothing", cascaded, removed)
		}
		if opts.blockedSet {
			t.Errorf("the blocked list was rewritten for %+v", removed)
		}
	}
}

// A `block rm` of the target does not take it either: the entry belongs to the
// link that derived it, and the target is not a blocked entry at all, so an ask
// naming it removes nothing and must leave the derivation standing.
func TestABlockRemovalOfTheTargetLeavesALinksDerivation(t *testing.T) {
	target := "/home/op/dotfiles/npmrc"
	existing := []config.BlockedPath{{Path: "/home/op/.npmrc", DerivedFrom: target}}

	kept, removed, cascaded := withoutBlocked(existing, []config.BlockedPath{{Path: target}})

	if removed[0].Path != "" {
		t.Errorf("removed = %+v, want nothing: the target is no blocked entry", removed)
	}
	if len(cascaded) != 0 {
		t.Errorf("cascaded = %+v, want the link's own entry left standing", cascaded)
	}
	if len(kept) != 1 {
		t.Errorf("kept = %+v, want the entry untouched", kept)
	}
}

// The resolution happens before the tree rule, or an entry naming a symlink to
// an enrolled tree would pass a check made against the spelling rather than
// against the file, and refuse the agent every file in its own checkout.
func TestAddLinkResolvesBeforeItChecksTheTree(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "")
	tree, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if err := agentcfg.RecordEnrolment(dir,
		agentcfg.EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(home, ".dotfiles")
	if err := os.Symlink(tree, link); err != nil {
		t.Fatal(err)
	}

	_, _, err = AddLink(Options{ConfigDir: dir},
		config.Link{Ref: "a/b", Path: link, Type: "json", Key: "k"})

	if err == nil {
		t.Fatal("a link resolving to an enrolled tree was accepted")
	}
	if !strings.Contains(err.Error(), "enrolled tree") {
		t.Errorf("the refusal does not say why: %v", err)
	}
	if !strings.Contains(err.Error(), tree) {
		t.Errorf("the refusal names the spelling and not the file: %v", err)
	}
}
