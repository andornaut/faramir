package hostfs

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
)

// The two shapes these methods have: one that writes, and one that computes the
// same answer and writes nothing.
var (
	realFS = FS{}
	dryFS  = FS{DryRun: true}
)

// The directories these walk (the config directory and the secrets directory)
// can sit inside the operator's own home under --config-dir, and the operator is
// the uid the agent runs as. A path-based chmod there would take root's mode
// change to whatever the link points at.
func TestEnsureOwnershipRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	_, err := realFS.EnsureOwnership(link, 0o644, Keep, Keep)
	if err == nil {
		t.Fatal("ensureOwnership followed a symlink")
	}
	info, statErr := os.Stat(target)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the link's target is %04o, want 0600: the mode was applied through it", got)
	}
}

// A regular file is still repaired.
func TestEnsureOwnershipFixesTheMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte("x"), 0o666); err != nil {
		t.Fatal(err)
	}
	// Chmod, not the WriteFile mode: WriteFile is masked by the umask, so under the
	// common 022 the file lands 0644 already and there is nothing for ensureOwnership
	// to fix. chmod ignores the umask, so the starting mode is wrong on any host.
	if err := os.Chmod(path, 0o666); err != nil {
		t.Fatal(err)
	}
	changed, err := realFS.EnsureOwnership(path, 0o644, Keep, Keep)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("no change reported for a file whose mode was wrong")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o644 {
		t.Errorf("mode is %04o, want 0644", got)
	}
	// Idempotent: a second run has nothing to do.
	if changed, err := realFS.EnsureOwnership(path, 0o644, Keep, Keep); err != nil || changed {
		t.Errorf("second run: changed=%v err=%v, want false/nil", changed, err)
	}
}

// The audit log's owner is otherwise whichever uid writes the first record, and
// `faramir vault edit` runs as root.
func TestEnsurePrivateFileCreatesItPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	changed, err := realFS.EnsurePrivateFile(path, Keep, Keep)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("creating the file was not reported as a change")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	// Asserted rather than left to the umask the process happens to hold.
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode is %04o, want 0600", got)
	}
	if info.Size() != 0 {
		t.Errorf("size is %d, want an empty file", info.Size())
	}

	if changed, err := realFS.EnsurePrivateFile(path, Keep, Keep); err != nil || changed {
		t.Errorf("second run: changed=%v err=%v, want false/nil", changed, err)
	}
}

// An existing log keeps its records: this asserts ownership, it does not write.
func TestEnsurePrivateFileKeepsTheContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(`{"log_id":"x"}`+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	changed, err := realFS.EnsurePrivateFile(path, Keep, Keep)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Error("a wrong mode on an existing file was not reported")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"log_id":"x"}`+"\n" {
		t.Errorf("contents are %q, want the record left alone", body)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("mode is %04o, want 0600", got)
	}
}

// A dry run is unprivileged, so a file it cannot look at is reported as no
// change rather than as a failure that stops the whole plan being produced.
func TestEnsurePrivateFileIsQuietUnderADryRun(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root can look inside a 0000 directory")
	}
	dir := filepath.Join(t.TempDir(), "logs")
	if err := os.Mkdir(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })

	changed, err := dryFS.EnsurePrivateFile(filepath.Join(dir, "audit.log"), Keep, Keep)
	if err != nil {
		t.Fatalf("dry run failed on a directory it cannot enter: %v", err)
	}
	if changed {
		t.Error("a change was reported for a file that could not be looked at")
	}
}

// The repair goes through a descriptor, so the file checked and the file changed
// are the same file.
func TestChmodAndChownRefusesASymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := chmodAndChown(link, 0o644, Keep, Keep)
	if err == nil {
		t.Fatal("chmodAndChown followed a symlink")
	}
	if !errors.Is(err, syscall.ELOOP) {
		t.Errorf("error is %v, want ELOOP from O_NOFOLLOW", err)
	}
}

// own=true is how a directory the operator created is taken back: the mode and
// owner asserted there are what stop the account the agent runs as writing the
// drop-ins that choose what the executor runs. Through a symlink the chmod
// lands on the target while the chown lands on the link, so the link keeps its
// operator ownership and the step reports success.
func TestEnsureDirRefusesASymlinkItWouldAssertOn(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "secrets")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	if _, err := realFS.EnsureDir(link, 0o755, Keep, Keep, true); err == nil {
		t.Error("ensureDir asserted a mode through a symlink")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("the link's target is %04o, want 0700: the mode was applied through it", got)
	}
}

// own=false only needs the directory to be there, and asserts nothing, so a
// symlinked one is not this install's business: the account homes and the agent
// config's parent are the operator's to arrange.
func TestEnsureDirAllowsASymlinkItOnlyReadsThrough(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(base, "state")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}

	changed, err := realFS.EnsureDir(link, 0o755, Keep, Keep, false)
	if err != nil {
		t.Errorf("ensureDir(own=false) refused a symlink it does not touch: %v", err)
	}
	if changed {
		t.Error("own=false reported a change")
	}
	info, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf("the link's target is %04o, want 0700: it was modified anyway", got)
	}
}

// The question both preflights ask of the directories a write would create.
// A symlinked component is the one that matters: the write would land wherever
// it points rather than under root, and refuseUnwritable cannot answer for it
// while the directory itself is not there.
func TestRefuseUnenterableDirsNamesASymlinkedComponent(t *testing.T) {
	root := t.TempDir()
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, ".config")); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}

	refused := RefuseUnenterableDirs(root, 0o700, os.Getuid(), os.Getgid(), []string{
		".claude/settings.json",          // a real directory that is already there
		".config/opencode/opencode.json", // through the symlink
		".pi/agent/AGENTS.md",            // a directory that does not exist yet
	})

	if len(refused) != 1 {
		t.Fatalf("refused %v, want the symlinked component alone", refused)
	}
	if !strings.Contains(refused[0], "symlink") {
		t.Errorf("the refusal does not say why: %s", refused[0])
	}
	// Asked through a dry run, so nothing was created for the two it accepted.
	if _, err := os.Stat(filepath.Join(root, ".pi")); err == nil {
		t.Error("the check created a directory: it must answer and write nothing")
	}
}

// A home where an agent's settings directory is a symlink into a dotfiles
// checkout is one writeAgentFiles writes to happily: it calls ensureDir with
// own=false, which reads through the link on purpose. So the precondition that
// stands in for that write has to accept it too, or `init`, `link add` and
// `block add` all refuse an install that would have worked.
//
// The tree side keeps the strict rule, which refuseUnenterableDirs is for: there
// the directory is handed to the client group, so a link would hand out whatever
// it points at.
func TestAHomeAcceptsASymlinkedAgentDirectory(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, "dotfiles", "claude")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	paths := []string{".claude/settings.json"}

	if refused := RefuseUncreatableDirs(home, 0o700, Keep, Keep, paths); len(refused) > 0 {
		t.Errorf("a symlinked agent directory was refused, though the write accepts "+
			"it: %s", refused[0])
	}
	// And the tree's question still refuses it, the two being different questions.
	if refused := RefuseUnenterableDirs(home, 0o700, Keep, Keep, paths); len(refused) == 0 {
		t.Error("the tree-side check accepted a symlinked component")
	}
}

// A directory that is not there is not a refusal either: the write creates it.
func TestAHomeAcceptsAnAgentDirectoryThatIsNotThereYet(t *testing.T) {
	home := t.TempDir()
	if refused := RefuseUncreatableDirs(home, 0o700, Keep, Keep,
		[]string{".claude/settings.json"}); len(refused) > 0 {
		t.Errorf("a directory the write would create was refused: %s", refused[0])
	}
}

// The directory an enrolled file lands in is where the sticky bit belongs: the
// tree is group-writable by the account brokered commands run as, unlink is a
// permission on the directory, and without it that account can delete the rules
// file and put its own there. sharetree's walk sets it on the directories a kept
// file sits in, but it runs before an enrolment writes anything, so a directory
// created here has to carry it from the start or the tree stays open until a
// second enrolment settles it.
func TestADirectoryCreatedForAnEnrolledFileIsSticky(t *testing.T) {
	root := t.TempDir()
	const (
		mode = os.FileMode(0o770) | os.ModeSetgid
		leaf = mode | os.ModeSticky
	)
	if err := realFS.EnsureDirsIn(root, filepath.Join(root, ".pi", "extensions"),
		mode, leaf, Keep, Keep); err != nil {
		t.Fatal(err)
	}

	// Only the last component. sharetree names the directory the file sits in and
	// no level above it, so a level made sticky here would be one the next run's
	// walk clears, and the enrolment would report a change every time.
	for _, tc := range []struct {
		rel  string
		want os.FileMode
	}{
		{".pi", mode},
		{filepath.Join(".pi", "extensions"), leaf},
	} {
		info, err := os.Stat(filepath.Join(root, tc.rel))
		if err != nil {
			t.Fatal(err)
		}
		if got := chmodBitsOf(info.Mode()); got != tc.want {
			t.Errorf("%s is %v, want %v", tc.rel, got, tc.want)
		}
	}
}

// Pinned to the root: a caller that names a directory outside it is refused
// before anything is created. The parent itself is the case a prefix test alone
// does not cover, "." relative to it being ".." with nothing after it.
func TestADirectoryOutsideTheRootIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		rel  string
	}{
		{"the root's own parent", ".."},
		{"a sibling of the root", filepath.Join("..", "elsewhere")},
		{"a directory under a sibling", filepath.Join("..", "elsewhere", "deeper")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := filepath.Join(t.TempDir(), "root")
			if err := os.Mkdir(root, 0o755); err != nil {
				t.Fatal(err)
			}
			outside := filepath.Join(root, tc.rel)
			_, before := os.Stat(outside)
			err := realFS.EnsureDirsIn(root, outside, 0o755, 0o755, Keep, Keep)
			if err == nil {
				t.Fatalf("%s was accepted", outside)
			}
			if !strings.Contains(err.Error(), "outside") {
				t.Errorf("error = %q, want it to say the path is outside the root", err)
			}
			// The root's own parent is there already; the others are not, and a
			// refusal that created one would have written outside the root.
			if _, after := os.Stat(outside); before != nil && after == nil {
				t.Errorf("%s was created anyway", outside)
			}
		})
	}
}

// chmodBitsOf is the bits a chmod applies, ModeDir and the rest of the type
// being no part of what was asked for.
func chmodBitsOf(mode os.FileMode) os.FileMode {
	return mode & (os.ModePerm | os.ModeSetuid | os.ModeSetgid | os.ModeSticky)
}

// A write goes through a temporary file beside the target and renames it into
// place. The rename takes the name, so removing it afterwards removes whatever
// holds that name then -- which, with a second writer in flight, is the
// temporary file that writer just created O_EXCL. Its own chmod then fails with
// an ENOENT about a path it made itself, which says nothing about the collision
// that caused it.
func TestAFinishedWriteDoesNotRemoveAnotherWritersTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("start\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	errs := make([]error, 12)
	for i := range errs {
		wg.Go(func() {
			body := fmt.Appendf(nil, "written by %d\n", i)
			_, errs[i] = realFS.WriteFile(path, body, 0o644, Keep, Keep)
		})
	}
	wg.Wait()
	for i, err := range errs {
		if err == nil {
			continue
		}
		// The one collision a concurrent write may report: the temporary name was
		// taken. Anything else is this bug, or another.
		if !strings.Contains(err.Error(), "is already there") {
			t.Errorf("writer %d failed with %v, want nil or the temporary-file "+
				"collision", i, err)
		}
	}
	// And whatever won, the file is one writer's bytes rather than a mix, and no
	// temporary file is left behind.
	if _, err := os.Stat(path + ".faramir-tmp"); !os.IsNotExist(err) {
		t.Errorf("a temporary file was left at %s.faramir-tmp", path)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), "written by ") {
		t.Errorf("the file is %q, which is no writer's whole output", body)
	}
}

// An edit of a file's contents is a read-modify-write: the caller reads it,
// changes what it carries and writes the whole thing back. Two of those leave
// one change, and without this both report the one they made as written.
//
// Asked while the temporary name is held, so it decides something: O_EXCL admits
// one writer at a time, and a second either fails on that or gets here after the
// first has renamed and sees the file it read is gone.
func TestAWriteExpectingWhatItReadIsRefusedWhenThatChanged(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(path, []byte("first\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	digest := func() []byte {
		body, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		sum := sha256.Sum256(body)
		return sum[:]
	}
	was := digest()
	if _, err := realFS.WriteFileExpecting(path, []byte("edited\n"), 0o644, was); err != nil {
		t.Fatalf("a write onto the file it read was refused: %v", err)
	}

	// The same expectation again, now stale.
	_, err := realFS.WriteFileExpecting(path, []byte("second edit\n"), 0o644, was)
	if err == nil {
		t.Fatal("a write onto a file something else had changed was accepted")
	}
	for _, want := range []string{path, "changed while this was working on it"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not say %q: %v", want, err)
		}
	}
	// And it wrote nothing: the loser must not leave half an edit behind.
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "edited\n" {
		t.Errorf("the file is %q, so the refused write landed anyway", body)
	}

	// A nil digest is a caller whose read found no file, not a caller that read
	// nothing: one is here now, so another run created it and renaming over it
	// would take whatever that run wrote.
	_, err = realFS.WriteFileExpecting(path, []byte("third\n"), 0o644, nil)
	if err == nil {
		t.Fatal("a write expecting no file was accepted onto one that is there")
	}
	if !strings.Contains(err.Error(), "created while this was working on it") {
		t.Errorf("the refusal does not say the file appeared: %v", err)
	}

	// And a write that is not an edit of anything is refused for nothing, which
	// is every other write this install makes.
	plain := filepath.Join(filepath.Dir(path), "plain.toml")
	if _, err := realFS.WriteFile(plain, []byte("first\n"), 0o644, Keep, Keep); err != nil {
		t.Errorf("a plain write was refused: %v", err)
	}
	if _, err := realFS.WriteFile(plain, []byte("second\n"), 0o644, Keep, Keep); err != nil {
		t.Errorf("a plain rewrite was refused: %v", err)
	}
}

// The first write of a record has no digest to expect, and treating that as
// nothing to check left the window the digest exists to close: two runs each
// find no file, each write, and one entry is gone with no error. The second is
// refused instead.
func TestAFirstWriteIsRefusedWhenAnotherRunGotThereFirst(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enrolled.json")
	realFS := FS{}

	// Both runs read: neither finds a file.
	// The first writes.
	if _, err := realFS.WriteFileExpecting(path, []byte("first\n"), 0o600, nil); err != nil {
		t.Fatalf("a first write was refused: %v", err)
	}
	// The second, still holding what its own read found, is refused.
	if _, err := realFS.WriteFileExpecting(path, []byte("second\n"), 0o600, nil); err == nil {
		t.Fatal("the second first-write was accepted, so the first run's record is gone")
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "first\n" {
		t.Errorf("the file is %q, so the refused write landed anyway", body)
	}
}

// The two things a nil digest can mean, which is why the flag beside it exists.
// `init` renders the whole config rather than editing what it read, so it
// expects nothing and must still be able to rewrite a file that is there; a
// command that read the entries and found no file expects absence, and a file
// that appeared since is another run it must not write over.
//
// Conflating them left `faramir init` unable to rewrite its own config on
// every host that already had one.
func TestAWriteThatReadNothingIsNotAWriteThatFoundNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	realFS := FS{}

	if _, err := realFS.WriteFile(path, []byte("first\n"), 0o644, Keep, Keep); err != nil {
		t.Fatal(err)
	}
	// A render: it read nothing, so nothing is expected and the write lands.
	if _, err := realFS.WriteFile(path, []byte("second\n"), 0o644, Keep, Keep); err != nil {
		t.Errorf("a render onto an existing file was refused: %v", err)
	}
	// An edit whose read found no file: one is here, so another run wrote it.
	if _, err := realFS.WriteFileExpecting(path, []byte("third\n"), 0o644, nil); err == nil {
		t.Error("a write expecting no file was accepted onto one that is there")
	}
}

// A plain file is pinned the same way a followed link is. The check and the
// write are two operations, and a path checked and then written by path is
// resolved twice: the directories these sit in are the operator's, and in an
// enrolled tree the client group's, so either can replace one in between.
func TestAPlainEditedFileIsPinnedToo(t *testing.T) {
	home := t.TempDir()
	realDir := filepath.Join(home, "agent")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realDir, "settings.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	spot, err := (FS{}).EditedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.Close()
	if spot.root == nil {
		t.Fatal("a plain file left no pinned directory, so the write resolves the " +
			"path a second time")
	}

	decoy := filepath.Join(home, "decoy")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, realDir); err != nil {
		t.Fatal(err)
	}

	if _, err := (FS{}).WriteEdited(spot, []byte(`{"a":1}`+"\n"), 0o600, Keep, Keep); err != nil {
		t.Fatal(err)
	}

	if Exists(filepath.Join(decoy, "settings.json")) {
		t.Error("the write followed the swapped directory")
	}
	body, err := os.ReadFile(filepath.Join(home, "moved", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"a":1}`+"\n" {
		t.Errorf("the write did not land in the directory that was checked:\n%s", body)
	}
}

// A followed link is written through a descriptor opened on the target's
// directory, so the path is resolved once. What that buys, asserted the only
// way it can be from here: the directory the write goes into is the one that
// was checked, so replacing it afterwards reaches nothing this run does.
func TestAFollowedLinkIsWrittenThroughAPinnedDirectory(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "AGENTS.md")
	realDir := filepath.Join(home, "dotfiles")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(realDir, "AGENTS.md")
	if err := os.WriteFile(target, []byte("# Mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	spot, err := (FS{}).EditedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.Close()
	if spot.root == nil {
		t.Fatal("a followed link left no pinned directory, so the write resolves " +
			"the path a second time")
	}

	// The directory is swapped after the check, as an agent owning it could.
	// The descriptor still names the old one, so that is where the write lands.
	decoy := filepath.Join(home, "decoy")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, realDir); err != nil {
		t.Fatal(err)
	}

	if _, err := (FS{}).WriteEdited(spot, []byte("# Written\n"), 0o600, Keep, Keep); err != nil {
		t.Fatal(err)
	}

	if Exists(filepath.Join(decoy, "AGENTS.md")) {
		t.Error("the write followed the swapped directory")
	}
	body, err := os.ReadFile(filepath.Join(home, "moved", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# Written\n" {
		t.Errorf("the write did not land in the directory that was checked:\n%s", body)
	}
}

// And it keeps the temp-and-rename, so a run that dies partway leaves the file
// it found rather than half of a new one.
func TestAFollowedLinkKeepsTheTempAndRename(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "AGENTS.md")
	target := filepath.Join(home, "real.md")
	if err := os.WriteFile(target, []byte("# Mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	spot, err := (FS{}).EditedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.Close()

	// A temp already sitting there is an error rather than something to
	// truncate: it is not this run's file, and the target is untouched.
	planted := target + ".faramir-tmp"
	if err := os.WriteFile(planted, []byte("theirs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (FS{}).WriteEdited(spot, []byte("# Written\n"), 0o600, Keep, Keep); err == nil {
		t.Error("a planted temp file was written over")
	}
	if body, readErr := os.ReadFile(target); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != "# Mine\n" {
		t.Errorf("the target was changed by a write that failed:\n%s", body)
	}
}
