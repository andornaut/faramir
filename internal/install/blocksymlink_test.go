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

// A rule matches the path a command names, so a link and its target are two
// ways to the same file and an entry for one covers the other only by accident.
// These hold an add to recording both, and a removal to taking both away.

// linkedFile is a file and a symlink to it, both absolute and both already
// resolved: a temporary directory reached through a symlinked ancestor would
// make the target this expects and the target EvalSymlinks returns two strings.
func linkedFile(t *testing.T) (link, target string) {
	t.Helper()
	dir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	target = filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link = filepath.Join(dir, "config.json")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	return link, target
}

func TestADeclaredSymlinkDerivesItsTarget(t *testing.T) {
	link, target := linkedFile(t)
	dir := layouttest.BlockConfigDir(t, "")

	derived, skipped := derivations(dir, []config.BlockedPath{{Path: link, Strict: true}})

	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want nothing", skipped)
	}
	if len(derived) != 1 {
		t.Fatalf("derived = %+v, want the target of the symlink", derived)
	}
	if derived[0].Path != target {
		t.Errorf("path = %q, want %q", derived[0].Path, target)
	}
	if derived[0].DerivedFrom != link {
		t.Errorf("derived_from = %q, want %q", derived[0].DerivedFrom, link)
	}
	// The strictness of the entry that reached the file, or the looser spelling
	// would be the one to name it by.
	if !derived[0].Strict {
		t.Error("the derived entry is not strict, and the entry it came from is")
	}
	// What is derived is written into the config, so it is held to what the
	// loader accepts before it goes anywhere near one.
	if err := config.ValidateBlocked(derived[0]); err != nil {
		t.Errorf("the derived entry does not load: %v", err)
	}
}

// Nothing is derived where there is nothing to resolve. A plain file resolves
// to itself; an absent path resolves to nothing at all, which an entry is
// allowed to name, being a key on a volume that is not always mounted; and a
// wildcard names no single file, its literal parent already bounding the rule.
func TestNothingIsDerivedWhereThereIsNoSymlink(t *testing.T) {
	base, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	plain := filepath.Join(base, "volume.key")
	if err := os.WriteFile(plain, []byte("key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dir := layouttest.BlockConfigDir(t, "")
	for _, path := range []string{
		plain,
		filepath.Join(base, "not-mounted", "volume.key"),
		filepath.Join(base, "sentry-*"),
	} {
		derived, skipped := derivations(dir, []config.BlockedPath{{Path: path}})
		if len(derived) != 0 || len(skipped) != 0 {
			t.Errorf("%s: derived %+v and skipped %+v, want neither", path, derived, skipped)
		}
	}
}

// A command entry names no file, so there is nothing under it to resolve and
// nothing to derive.
func TestACommandEntryDerivesNothing(t *testing.T) {
	dir := layouttest.BlockConfigDir(t, "")
	derived, skipped := derivations(dir, []config.BlockedPath{{Command: "op read"}})
	if len(derived) != 0 || len(skipped) != 0 {
		t.Errorf("derived %+v and skipped %+v, want neither", derived, skipped)
	}
}

// The declared entry is the one an operator removes, and the derivation exists
// because that entry reached the file. Left behind, it would be a rule no entry
// explains and one the next converge reports as undeclared.
func TestRemovingAPathTakesWhatItDerived(t *testing.T) {
	link := "/home/op/.config/app/config.json"
	target := "/home/op/dotfiles/app/config.json"
	existing := []config.BlockedPath{
		{Path: link},
		{Path: target, DerivedFrom: link},
		{Path: "/etc/luks/volume.key"},
	}

	kept, removed, cascaded := withoutBlocked(existing, []config.BlockedPath{{Path: link}})

	if len(kept) != 1 || kept[0].Path != "/etc/luks/volume.key" {
		t.Errorf("kept = %+v, want the unrelated entry alone", kept)
	}
	if removed[0].Path != link {
		t.Errorf("removed = %+v, want the declared path", removed)
	}
	if len(cascaded) != 1 || cascaded[0].Path != target {
		t.Errorf("cascaded = %+v, want the entry derived from it", cascaded)
	}
}

// An operator who declares the target on its own account owns that entry: it
// stops being the link's, so removing the link leaves it standing. What was
// declared is not something another entry's removal may take away.
func TestDeclaringADerivedPathTakesItOver(t *testing.T) {
	link := "/home/op/.config/app/config.json"
	target := "/home/op/dotfiles/app/config.json"
	derived := config.BlockedPath{Path: target, DerivedFrom: link}

	entries, changed := blockedWith([]config.BlockedPath{{Path: link}, derived},
		config.BlockedPath{Path: target})

	if !changed {
		t.Error("an entry that changed hands was reported unchanged")
	}
	if entries[1].DerivedFrom != "" {
		t.Errorf("derived_from = %q, want it cleared", entries[1].DerivedFrom)
	}
	if _, _, cascaded := withoutBlocked(entries,
		[]config.BlockedPath{{Path: link}}); len(cascaded) != 0 {
		t.Errorf("cascaded = %+v, want the operator's own entry left alone", cascaded)
	}
}

// A derivation over an entry the operator wrote says nothing new about it: the
// entry stays theirs, so a later `block rm` of the symlink leaves it.
func TestADerivationDoesNotTakeOverADeclaredEntry(t *testing.T) {
	target := "/home/op/dotfiles/app/config.json"
	declared := []config.BlockedPath{{Path: target}}

	entries, changed := blockedWith(declared,
		config.BlockedPath{Path: target, DerivedFrom: "/home/op/.config/app/config.json"})

	if changed {
		t.Error("an entry that was already declared was reported changed")
	}
	if entries[0].DerivedFrom != "" {
		t.Errorf("derived_from = %q, want the entry left as the operator wrote it",
			entries[0].DerivedFrom)
	}
}

// Both halves are said. The first is an entry the operator will meet in the
// config and in `block ls` without having typed it; the second is a file still
// reachable under a name no entry covers, which is the case a silent skip would
// leave them believing was closed.
func TestTheReportSaysWhatWasDerivedAndWhatWasNot(t *testing.T) {
	var report Report
	derivedWarnings(&report,
		[]config.BlockedPath{{Path: "/home/op/dotfiles/app.json", DerivedFrom: "/home/op/.app.json"}},
		[]config.BlockedPath{{Path: "/home/op/src/tree/.env", DerivedFrom: "/home/op/.env"}})

	if len(report.Warnings) != 2 {
		t.Fatalf("warnings = %q, want one for each", report.Warnings)
	}
	if !strings.Contains(report.Warnings[0], "/home/op/dotfiles/app.json") ||
		!strings.Contains(report.Warnings[0], "/home/op/.app.json") {
		t.Errorf("the derived warning names neither end of the link: %q", report.Warnings[0])
	}
	if !strings.Contains(report.Warnings[1], "not blocked") {
		t.Errorf("the skipped warning does not say the target is left open: %q",
			report.Warnings[1])
	}
}

// The key has to survive the file: an entry that renders without it is a
// derivation the next run reads as an entry the operator declared, and a
// `block rm` of the symlink then leaves the target blocked with nothing left
// to explain it.
func TestADerivedEntryRendersAndLoadsBack(t *testing.T) {
	layout := testLayout()
	derived := config.BlockedPath{
		Path:        "/home/op/dotfiles/app/config.json",
		DerivedFrom: "/home/op/.config/app/config.json",
		Strict:      true,
	}
	layout.Blocked = append(layout.Blocked, derived)

	body, err := agentcfg.Render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Load(path)
	if err != nil {
		t.Fatalf("the rendered config does not load: %v\n%s", err, body)
	}
	if len(cfg.Secret.Blocked) != 1 {
		t.Fatalf("loaded %+v, want the one entry", cfg.Secret.Blocked)
	}
	if got := cfg.Secret.Blocked[0]; got != derived {
		t.Errorf("loaded %+v, want %+v", got, derived)
	}
}

// A dotfiles checkout is exactly the kind of directory a config symlink points
// at, and it is often the tree the agent works in. Deriving an entry over one
// would refuse the agent every file in its own working directory, with a rule
// nobody typed and nothing in the config naming the tree. A file inside a tree
// is the ordinary entry and is derived like any other: what is refused is an
// entry that reaches the tree itself.
func TestATargetThatIsAnEnrolledTreeIsNotDerived(t *testing.T) {
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

	derived, skipped := derivations(dir, []config.BlockedPath{{Path: link}})

	if len(derived) != 0 {
		t.Errorf("derived %+v over an enrolled tree", derived)
	}
	// Said rather than passed over: the file is still reachable under the name
	// the entry does not cover, which the operator has to know.
	if len(skipped) != 1 || skipped[0].Path != tree {
		t.Errorf("skipped = %+v, want the target that was left alone", skipped)
	}

	// The boundary: a file inside the tree is the ordinary entry, and a symlink
	// pointing at one derives like any other. Refusing these too would leave
	// every dotfiles-managed credential covered under one name only.
	inside := filepath.Join(tree, ".env")
	if err := os.WriteFile(inside, []byte("TOKEN=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	insideLink := filepath.Join(home, ".env")
	if err := os.Symlink(inside, insideLink); err != nil {
		t.Fatal(err)
	}
	derived, skipped = derivations(dir, []config.BlockedPath{{Path: insideLink}})
	if len(skipped) != 0 {
		t.Errorf("skipped = %+v, want a file inside a tree derived like any other", skipped)
	}
	if len(derived) != 1 || derived[0].Path != inside {
		t.Errorf("derived = %+v, want %s", derived, inside)
	}
}

// A converge runs the same list every time, so an entry that two of its rules
// disagree about has to settle on one of them. The declared entry wins: a
// derivation that loosened it would be tightened again by the next run, and
// both runs would report a change to a host nothing was wrong with.
func TestADerivationDoesNotRestrikeADeclaredEntry(t *testing.T) {
	link := "/home/op/.config/app/config.json"
	target := "/home/op/dotfiles/app/config.json"
	declared := []config.BlockedPath{{Path: link}, {Path: target, Strict: true}}
	derivation := config.BlockedPath{Path: target, DerivedFrom: link}

	entries, changed := blockedWith(declared, derivation)
	if changed {
		t.Error("a derivation reported a change to an entry the operator declared")
	}
	if !entries[1].Strict {
		t.Error("the strictness the operator declared was loosened by a derivation")
	}
	// And a second pass over its own output is the same, which is what makes the
	// converge quiet rather than merely correct once.
	if _, changed := blockedWith(entries, derivation); changed {
		t.Error("the second converge of the same list reported a change")
	}
}

// It does own the entry it wrote, so the strictness of the declared symlink
// still reaches the target when that changes.
func TestADerivationRestrikesItsOwnEntry(t *testing.T) {
	link := "/home/op/.config/app/config.json"
	target := "/home/op/dotfiles/app/config.json"
	existing := []config.BlockedPath{
		{Path: link, Strict: true},
		{Path: target, DerivedFrom: link},
	}

	entries, changed := blockedWith(existing,
		config.BlockedPath{Path: target, Strict: true, DerivedFrom: link})

	if !changed {
		t.Error("a derived entry was left at the old strictness without a change reported")
	}
	if !entries[1].Strict {
		t.Error("the derived entry did not take the strictness of the entry that derived it")
	}
}
