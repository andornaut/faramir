package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/layouttest"
)

// A derived entry goes with the entry it was written for unless another entry
// still reaches its file. These hold a removal to that, and an add naming a
// symlink again to replacing what it derived before the link was repointed.

// twoLinks is a file and two symlinks to it, resolved the way linkedFile is.
func twoLinks(t *testing.T) (first, second, target string) {
	t.Helper()
	first, target = linkedFile(t)
	second = filepath.Join(filepath.Dir(target), "settings.json")
	if err := os.Symlink(target, second); err != nil {
		t.Fatal(err)
	}
	return first, second, target
}

func TestATargetStaysWhileAnotherSymlinkStillReachesIt(t *testing.T) {
	first, second, target := twoLinks(t)
	existing := []config.BlockedPath{{Path: first}, {Path: second}, {Path: target, DerivedFrom: first}}

	kept, _, cascaded, retained := withoutBlocked(existing, []config.BlockedPath{{Path: first}}, nil)

	if len(cascaded) != 0 {
		t.Errorf("cascaded = %+v, want the target kept for the other symlink", cascaded)
	}
	if len(retained) != 1 || retained[0].Path != target || retained[0].DerivedFrom != second {
		t.Errorf("retained = %+v, want the target, now derived from %s", retained, second)
	}
	if len(kept) != 2 || kept[1].Path != target || kept[1].DerivedFrom != second {
		t.Fatalf("kept = %+v, want the other symlink and the target re-derived from it", kept)
	}

	kept, _, cascaded, retained = withoutBlocked(kept, []config.BlockedPath{{Path: second}}, nil)

	if len(kept) != 0 || len(retained) != 0 {
		t.Errorf("kept = %+v, retained = %+v, want nothing left once both are gone", kept, retained)
	}
	if len(cascaded) != 1 || cascaded[0].Path != target {
		t.Errorf("cascaded = %+v, want the target to go with the last symlink", cascaded)
	}
}

// An entry that cannot be read is taken to reach the file: nothing can tell
// where it points, and the rule is kept rather than dropped.
func TestAnUnreadableEntryIsTakenToReachTheTarget(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads anything")
	}
	first, _, target := twoLinks(t)
	closed := filepath.Join(t.TempDir(), "closed")
	if err := os.Mkdir(closed, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(closed, 0o700) })
	unreadable := filepath.Join(closed, "config.json")
	existing := []config.BlockedPath{{Path: first}, {Path: unreadable}, {Path: target, DerivedFrom: first}}

	_, _, cascaded, retained := withoutBlocked(existing, []config.BlockedPath{{Path: first}}, nil)

	if len(cascaded) != 0 {
		t.Errorf("cascaded = %+v, want the target kept for the entry that cannot be read", cascaded)
	}
	if len(retained) != 1 || retained[0].DerivedFrom != unreadable {
		t.Errorf("retained = %+v, want the target derived from the unreadable entry", retained)
	}
}

// An entry that is not there does not reach anything: it is a rule waiting for
// a volume, and the target it might resolve to when mounted is not known.
func TestAnAbsentEntryDoesNotReachTheTarget(t *testing.T) {
	first, _, target := twoLinks(t)
	absent := filepath.Join(filepath.Dir(target), "absent.json")
	existing := []config.BlockedPath{{Path: first}, {Path: absent}, {Path: target, DerivedFrom: first}}

	kept, _, cascaded, _ := withoutBlocked(existing, []config.BlockedPath{{Path: first}}, nil)

	if len(cascaded) != 1 || cascaded[0].Path != target || len(kept) != 1 {
		t.Errorf("cascaded = %+v, kept = %+v, want the target to go", cascaded, kept)
	}
}

// A link's spelling stays while another link, or a block entry, still names
// the target it was derived from.
func TestASpellingStaysWhileAnotherEntryStillNamesTheTarget(t *testing.T) {
	target := "/home/op/dotfiles/npmrc"
	typed := "/home/op/.npmrc"
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \""+typed+"\"\n"+
		"derived_from = \""+target+"\"\n")
	configFile := filepath.Join(dir, "config.toml")
	other := config.Link{Ref: "npm/other", Path: target, Type: "text"}

	opts, cascaded, retained, err := withoutLinkDerivation(Options{ConfigDir: dir, links: []config.Link{other}},
		configFile, config.Link{Ref: "npm/token", Path: target, Type: "text"})

	if err != nil {
		t.Fatal(err)
	}
	if len(cascaded) != 0 {
		t.Errorf("cascaded = %+v, want the spelling kept for the other link", cascaded)
	}
	if len(retained) != 1 || retained[0].Path != typed || retained[0].DerivedFrom != target {
		t.Errorf("retained = %+v, want the spelling, still derived from the target", retained)
	}
	if !opts.blockedSet || len(opts.blocked) != 1 || opts.blocked[0].Path != typed {
		t.Errorf("blocked = %+v, want the spelling still there", opts.blocked)
	}
}

// A block entry naming the target keeps the spelling too: the file is declared
// under that name, and the spelling is another name for it.
func TestASpellingStaysWhileABlockEntryNamesTheTarget(t *testing.T) {
	target := "/home/op/dotfiles/npmrc"
	typed := "/home/op/.npmrc"
	dir := layouttest.BlockConfigDir(t, "[[secret.block]]\npath = \""+target+"\"\n\n"+
		"[[secret.block]]\npath = \""+typed+"\"\nderived_from = \""+target+"\"\n")
	configFile := filepath.Join(dir, "config.toml")

	_, cascaded, retained, err := withoutLinkDerivation(Options{ConfigDir: dir}, configFile,
		config.Link{Ref: "npm/token", Path: target, Type: "text"})

	if err != nil {
		t.Fatal(err)
	}
	if len(cascaded) != 0 || len(retained) != 1 {
		t.Errorf("cascaded = %+v, retained = %+v, want the spelling kept", cascaded, retained)
	}
}

// Removing a symlink whose target a link still names says the file is still
// refused rather than that it is readable.
func TestTheRemovalSaysWhenALinkStillRefusesTheTarget(t *testing.T) {
	link := "/home/op/.config/app/config.json"
	target := "/home/op/dotfiles/app/config.json"
	var report Report

	derivedRemovalWarnings(&report, []config.BlockedPath{{Path: target, DerivedFrom: link}}, nil,
		[]config.Link{{Ref: "app/token", Path: target, Type: "text"}})

	if len(report.Warnings) != 1 || !strings.Contains(report.Warnings[0], "still refused by the [[secret.link]] entry for app/token") {
		t.Errorf("warnings = %q, want the link named", report.Warnings)
	}
	if strings.Contains(report.Warnings[0], "no longer blocked") {
		t.Errorf("warnings = %q, say the file is readable while a link refuses it", report.Warnings)
	}
}

// repointed is a symlink that pointed at one file when it was declared and
// points at another now, with the entries the first add wrote.
func repointed(t *testing.T) (link, old, now string, existing []config.BlockedPath) {
	t.Helper()
	link, old = linkedFile(t)
	now = filepath.Join(filepath.Dir(old), "credentials.new.json")
	if err := os.WriteFile(now, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(now, link); err != nil {
		t.Fatal(err)
	}
	return link, old, now, []config.BlockedPath{{Path: link}, {Path: old, DerivedFrom: link}}
}

func TestReAddingARepointedSymlinkReplacesWhatItDerived(t *testing.T) {
	link, old, now, existing := repointed(t)
	asked := []config.BlockedPath{{Path: link}}
	derived, _ := derivations(t.TempDir(), asked)

	kept, stale, retained := replaceDerived(existing, asked, derived, nil)

	if len(derived) != 1 || derived[0].Path != now {
		t.Fatalf("derived = %+v, want the file the link names now", derived)
	}
	if len(stale) != 1 || stale[0].Path != old {
		t.Errorf("stale = %+v, want the entry for the file it named before", stale)
	}
	if len(retained) != 0 {
		t.Errorf("retained = %+v, want nothing: no other entry names the old file", retained)
	}
	if len(kept) != 1 || kept[0].Path != link {
		t.Errorf("kept = %+v, want the symlink's own entry alone", kept)
	}
}

// A symlink that became a plain file derives nothing now, so what it derived
// before goes the same way.
func TestReAddingAFormerSymlinkDropsWhatItDerived(t *testing.T) {
	link, old := linkedFile(t)
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(link, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	existing := []config.BlockedPath{{Path: link}, {Path: old, DerivedFrom: link}}
	asked := []config.BlockedPath{{Path: link}}

	kept, stale, _ := replaceDerived(existing, asked, nil, nil)

	if len(stale) != 1 || stale[0].Path != old {
		t.Errorf("stale = %+v, want the entry for the file it used to name", stale)
	}
	if len(kept) != 1 {
		t.Errorf("kept = %+v, want the entry alone", kept)
	}
}

// A symlink that still names what it named is left as it is, and so is one
// that is not there to ask: an add naming either every run reports no change.
func TestReAddingAnUnchangedOrAbsentSymlinkReplacesNothing(t *testing.T) {
	link, target := linkedFile(t)
	absent := filepath.Join(filepath.Dir(target), "absent.json")
	existing := []config.BlockedPath{
		{Path: link}, {Path: target, DerivedFrom: link},
		{Path: absent}, {Path: "/mnt/vault/key", DerivedFrom: absent},
	}
	asked := []config.BlockedPath{{Path: link}, {Path: absent}}
	derived, _ := derivations(t.TempDir(), asked)

	kept, stale, retained := replaceDerived(existing, asked, derived, nil)

	if len(stale) != 0 || len(retained) != 0 {
		t.Errorf("stale = %+v, retained = %+v, want nothing touched", stale, retained)
	}
	if len(kept) != len(existing) {
		t.Errorf("kept = %+v, want every entry as it was", kept)
	}
}

// An add naming a link's target outright leaves the spelling the link derived:
// that entry resolves to the target, which is the add's own subject.
func TestReAddingATargetLeavesALinksSpelling(t *testing.T) {
	typed, target := linkedFile(t)
	existing := []config.BlockedPath{{Path: typed, DerivedFrom: target}, {Path: target}}
	asked := []config.BlockedPath{{Path: target}}

	kept, stale, _ := replaceDerived(existing, asked, nil, nil)

	if len(stale) != 0 || len(kept) != 2 {
		t.Errorf("stale = %+v, kept = %+v, want the link's spelling left alone", stale, kept)
	}
}

// The old target stays where another declared symlink still resolves to it,
// now derived from that one.
func TestAReplacedDerivationIsKeptForAnotherSymlink(t *testing.T) {
	link, old, _, existing := repointed(t)
	other := filepath.Join(filepath.Dir(old), "settings.json")
	if err := os.Symlink(old, other); err != nil {
		t.Fatal(err)
	}
	existing = append(existing, config.BlockedPath{Path: other})
	asked := []config.BlockedPath{{Path: link}}
	derived, _ := derivations(t.TempDir(), asked)

	kept, stale, retained := replaceDerived(existing, asked, derived, nil)

	if len(stale) != 0 {
		t.Errorf("stale = %+v, want the old target kept for the other symlink", stale)
	}
	if len(retained) != 1 || retained[0].Path != old || retained[0].DerivedFrom != other {
		t.Errorf("retained = %+v, want the old target derived from %s", retained, other)
	}
	if len(kept) != 3 {
		t.Errorf("kept = %+v, want every entry still there", kept)
	}
}

// A link typed through one symlink and a block entry declaring another, both
// to one file. Removing the block entry takes its target, the link still
// refusing the file, and the link's spelling stays for the link. Nothing is
// kept by a derived entry that is itself a symlink: two such entries reaching
// each other would outlive everything that was declared.
func TestADerivedSpellingDoesNotKeepATargetAlive(t *testing.T) {
	typed, declared, target := twoLinks(t)
	links := []config.Link{{Ref: "gh/token", Path: target}}
	existing := []config.BlockedPath{
		{Path: typed, DerivedFrom: target},
		{Path: declared},
		{Path: target, DerivedFrom: declared},
	}

	kept, _, cascaded, retained := withoutBlocked(existing, []config.BlockedPath{{Path: declared}}, links)

	if len(cascaded) != 1 || cascaded[0].Path != target {
		t.Errorf("cascaded = %+v, want the target to go with the entry that derived it", cascaded)
	}
	if len(retained) != 1 || retained[0].Path != typed || retained[0].DerivedFrom != target {
		t.Errorf("retained = %+v, want the link's spelling kept by the link", retained)
	}
	if len(kept) != 1 || kept[0].Path != typed {
		t.Errorf("kept = %+v, want the link's spelling alone", kept)
	}
}

// An entry that goes is a source taken away in turn: what was derived from it
// goes as well, unless something else still reaches it.
func TestACascadeReachesWhatTheCascadedEntryDerived(t *testing.T) {
	typed, declared, target := twoLinks(t)
	existing := []config.BlockedPath{
		{Path: declared},
		{Path: target, DerivedFrom: declared},
		{Path: typed, DerivedFrom: target},
	}

	kept, _, cascaded, retained := withoutBlocked(existing, []config.BlockedPath{{Path: declared}}, nil)

	if len(kept) != 0 || len(retained) != 0 {
		t.Errorf("kept = %+v, retained = %+v, want nothing left", kept, retained)
	}
	if len(cascaded) != 2 || cascaded[0].Path != target || cascaded[1].Path != typed {
		t.Errorf("cascaded = %+v, want the target and then what was derived from it", cascaded)
	}
}
