package asaccount

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"
)

// The refusal an operator acts on is a directory, not the file: a config is
// usually world-readable and what stops the broker is a parent it cannot enter.
// A report naming the file sends them to chmod the wrong thing.
func TestBlockingDirNamesTheDirectoryAndNotTheFile(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skipf("no current user to ask about: %v", err)
	}
	if me.Uid == "0" {
		t.Skip("root enters a directory whatever its mode, so there is no closed door to meet")
	}

	// A chain of three, so the answer is the first closed one rather than the
	// last one looked at.
	root := t.TempDir()
	outer := filepath.Join(root, "outer")
	inner := filepath.Join(outer, "inner")
	if err := os.MkdirAll(inner, 0o755); err != nil {
		t.Fatal(err)
	}
	configFile := filepath.Join(inner, "config.toml")
	if err := os.WriteFile(configFile, []byte("[command]\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := BlockingDir(me.Username, configFile); got != "" {
		t.Errorf("blockingDir = %q with every directory open, want none", got)
	}

	// The middle one shut. Restored by the cleanup below, or t.TempDir cannot
	// remove what it made.
	if err := os.Chmod(outer, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(outer, 0o755) })
	if got := BlockingDir(me.Username, configFile); got != outer {
		t.Errorf("blockingDir = %q, want %q, the first directory that cannot be entered", got, outer)
	}

	// And the one nearest the file, when the ones above it are open: the walk
	// runs top down, so a closed directory deeper in is still found.
	if err := os.Chmod(outer, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(inner, 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(inner, 0o755) })
	if got := BlockingDir(me.Username, configFile); got != inner {
		t.Errorf("blockingDir = %q, want %q", got, inner)
	}
}

// An account nothing can name is not a closed door: answering with a directory
// would send an operator to fix a mode that is not the problem.
func TestBlockingDirNamesNothingForAnAccountItCannotResolve(t *testing.T) {
	dir := t.TempDir()
	configFile := filepath.Join(dir, "config.toml")
	if err := os.WriteFile(configFile, []byte("[command]\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := BlockingDir("no-such-account-here", configFile); got != "" {
		t.Errorf("blockingDir = %q for an account that does not exist", got)
	}
}

// Which class the kernel judges an account by, and the group case in
// particular: the config under a home is reached by the client group, so a
// check that ignored group membership would report a directory faramir had
// just granted as still closed.
func TestEnterableJudgesOneClassTheWayTheKernelDoes(t *testing.T) {
	const uid, ownGroup, otherGroup = 1000, 50, 60
	groups := map[int]bool{ownGroup: true}
	for _, tc := range []struct {
		what  string
		mode  os.FileMode
		owner int
		group int
		want  bool
	}{
		{"the owner, with owner execute", 0o700, uid, otherGroup, true},
		{"the owner, without it", 0o600, uid, otherGroup, false},
		// The owner is judged by the owner bit alone: an open group does not
		// rescue a directory whose owner bits refuse.
		{"the owner, refused by owner bits but open to the group", 0o077, uid, ownGroup, false},
		{"a member of the group, with group execute", 0o710, 0, ownGroup, true},
		{"a member of the group, without it", 0o700, 0, ownGroup, false},
		// The case the client group exists for, and the one this whole check is
		// about: not the owner, in the group, group execute only.
		{"a member of the group, no read and no write", 0o010, 0, ownGroup, true},
		{"in no relevant group, with other execute", 0o711, 0, otherGroup, true},
		{"in no relevant group, without it", 0o710, 0, otherGroup, false},
		// Group bits do not rescue an account that is not in that group.
		{"not in the group that has execute", 0o070, 0, otherGroup, false},
	} {
		if got := enterable(uid, groups, tc.mode, tc.owner, tc.group); got != tc.want {
			t.Errorf("enterable(mode %04o, owner %d, group %d) = %v, want %v: %s",
				tc.mode, tc.owner, tc.group, got, tc.want, tc.what)
		}
	}
}
