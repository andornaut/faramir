package install

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
	realFS = fsys{}
	dryFS  = fsys{dryRun: true}
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

	_, err := realFS.ensureOwnership(link, 0o644, keep, keep)
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
	changed, err := realFS.ensureOwnership(path, 0o644, keep, keep)
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
	if changed, err := realFS.ensureOwnership(path, 0o644, keep, keep); err != nil || changed {
		t.Errorf("second run: changed=%v err=%v, want false/nil", changed, err)
	}
}

// The audit log's owner is otherwise whichever uid writes the first record, and
// `faramir vault edit` runs as root.
func TestEnsurePrivateFileCreatesItPrivate(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")

	changed, err := realFS.ensurePrivateFile(path, keep, keep)
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

	if changed, err := realFS.ensurePrivateFile(path, keep, keep); err != nil || changed {
		t.Errorf("second run: changed=%v err=%v, want false/nil", changed, err)
	}
}

// An existing log keeps its records: this asserts ownership, it does not write.
func TestEnsurePrivateFileKeepsTheContents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	if err := os.WriteFile(path, []byte(`{"log_id":"x"}`+"\n"), 0o666); err != nil {
		t.Fatal(err)
	}
	changed, err := realFS.ensurePrivateFile(path, keep, keep)
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

	changed, err := dryFS.ensurePrivateFile(filepath.Join(dir, "audit.log"), keep, keep)
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
	err := chmodAndChown(link, 0o644, keep, keep)
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

	if _, err := realFS.ensureDir(link, 0o755, keep, keep, true); err == nil {
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

	changed, err := realFS.ensureDir(link, 0o755, keep, keep, false)
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

	refused := refuseUnenterableDirs(root, 0o700, os.Getuid(), os.Getgid(), []string{
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

	if refused := refuseUncreatableDirs(home, 0o700, keep, keep, paths); len(refused) > 0 {
		t.Errorf("a symlinked agent directory was refused, though the write accepts "+
			"it: %s", refused[0])
	}
	// And the tree's question still refuses it, the two being different questions.
	if refused := refuseUnenterableDirs(home, 0o700, keep, keep, paths); len(refused) == 0 {
		t.Error("the tree-side check accepted a symlinked component")
	}
}

// A directory that is not there is not a refusal either: the write creates it.
func TestAHomeAcceptsAnAgentDirectoryThatIsNotThereYet(t *testing.T) {
	home := t.TempDir()
	if refused := refuseUncreatableDirs(home, 0o700, keep, keep,
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
	if err := realFS.ensureDirsIn(root, filepath.Join(root, ".pi", "extensions"),
		mode, leaf, keep, keep); err != nil {
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
			_, errs[i] = realFS.writeFile(path, body, 0o644, keep, keep)
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
	if _, err := realFS.writeFileExpecting(path, []byte("edited\n"), 0o644,
		keep, keep, was); err != nil {
		t.Fatalf("a write onto the file it read was refused: %v", err)
	}

	// The same expectation again, now stale.
	_, err := realFS.writeFileExpecting(path, []byte("second edit\n"), 0o644,
		keep, keep, was)
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

	// A write that expects nothing is every other write this install makes.
	if _, err := realFS.writeFileExpecting(path, []byte("third\n"), 0o644,
		keep, keep, nil); err != nil {
		t.Errorf("a write expecting nothing was refused: %v", err)
	}
}
