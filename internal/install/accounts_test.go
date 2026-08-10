package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"testing"
)

// The secrets group holds nologin service accounts and belongs below GID_MIN.
// The wrong number warns about a group that is fine, or stays quiet about one
// that will collide.
func TestFirstLoginGID(t *testing.T) {
	for _, tc := range []struct {
		name    string
		content string
		want    int
	}{
		{
			// What Debian and Ubuntu ship, which is why GID_MIN is read.
			name: "shipped",
			content: "UID_MIN\t\t\t 1000\nUID_MAX\t\t\t60000\n" +
				"GID_MIN\t\t\t 1000\nGID_MAX\t\t\t60000\n" +
				"#SYS_GID_MIN\t\t  100\n#SYS_GID_MAX\t\t  999\n",
			want: 1000,
		},
		{
			name:    "raised",
			content: "GID_MIN 5000\n",
			want:    5000,
		},
		{
			// Prefixed, so the field name does not match.
			name:    "commented out",
			content: "#GID_MIN 5000\n",
			want:    1000,
		},
		{
			name:    "unparseable",
			content: "GID_MIN notanumber\n",
			want:    1000,
		},
		{
			name:    "absent",
			content: "UID_MIN 1000\n",
			want:    1000,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "login.defs")
			if err := os.WriteFile(path, []byte(tc.content), 0o644); err != nil {
				t.Fatal(err)
			}
			previous := loginDefs
			t.Cleanup(func() { loginDefs = previous })
			loginDefs = path

			if got := firstLoginGID(); got != tc.want {
				t.Errorf("firstLoginGID() = %d, want %d", got, tc.want)
			}
		})
	}
}

// The answer decides whether the secrets group is reported as
// misallocated.
func TestFirstLoginGIDWithoutLoginDefs(t *testing.T) {
	previous := loginDefs
	t.Cleanup(func() { loginDefs = previous })
	loginDefs = filepath.Join(t.TempDir(), "absent")

	if got := firstLoginGID(); got != 1000 {
		t.Errorf("firstLoginGID() = %d, want 1000", got)
	}
}

// [ssh] exec_group is the group the agent relay admits, so it has to be the
// exec account's real group rather than a group that merely shares its name.
func TestPrimaryGroupResolvesTheAccountsOwnGroup(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	gid, name, err := primaryGroup(self.Username)
	if err != nil {
		t.Fatalf("primaryGroup(%s): %v", self.Username, err)
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
	if _, _, err := primaryGroup("no-such-account-faramir-test"); err == nil {
		t.Error("primaryGroup accepted an account that does not exist")
	}
}
