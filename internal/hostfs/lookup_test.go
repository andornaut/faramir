package hostfs

// Looking up what is there.

import (
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

func TestMissingAncestors(t *testing.T) {
	root := t.TempDir()
	got := missingAncestors(filepath.Join(root, "a", "b"))
	want := []string{filepath.Join(root, "a"), filepath.Join(root, "a", "b")}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range got {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
	// An existing directory needs nothing created.
	if leftovers := missingAncestors(root); len(leftovers) != 0 {
		t.Errorf("got %v for a directory that is already there", leftovers)
	}
}

// [ssh] exec_group is the group the agent relay admits, so it has to be the
// exec account's real group rather than a group that merely shares its name.
func TestPrimaryGroupResolvesTheAccountsOwnGroup(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	gid, name, err := PrimaryGroup(self.Username)
	if err != nil {
		t.Fatalf("PrimaryGroup(%s): %v", self.Username, err)
	}
	if strconv.Itoa(gid) != self.Gid {
		t.Errorf("gid = %d, want %s", gid, self.Gid)
	}
	// The name is looked up from the gid, so it need not match the account.
	group, err := user.LookupGroupId(self.Gid)
	if err != nil {
		t.Skipf("gid %s has no group entry: %v", self.Gid, err)
	}
	if name != group.Name {
		t.Errorf("group = %q, want %q", name, group.Name)
	}
}

func TestPrimaryGroupRefusesAnAccountThatIsNotThere(t *testing.T) {
	if _, _, err := PrimaryGroup("no-such-account-faramir-test"); err == nil {
		t.Error("PrimaryGroup accepted an account that does not exist")
	}
}
