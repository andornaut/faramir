package sockutil

import (
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"testing"
)

// The socket authorisation, checked against a group file this test writes.
// Reading the host's /etc/group makes the result depend on the accounts that
// host happens to have, and a test that hunts for its own fixture skips rather
// than fails when the code it is checking breaks.

func useGroupFile(t *testing.T, body string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "group")
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	original := groupFile
	groupFile = path
	t.Cleanup(func() { groupFile = original })
}

const groupFixture = `root:x:0:
daemon:x:1:
faramir:x:900:alice,bob
faramir-clients:x:901:carol
empty:x:902:
malformed-line-with-no-fields
short:x:903
`

func TestGroupMembersReadsTheMemberList(t *testing.T) {
	useGroupFile(t, groupFixture)
	for _, tc := range []struct {
		name  string
		group string
		want  []string
	}{
		{"two members", "faramir", []string{"alice", "bob"}},
		{"one member", "faramir-clients", []string{"carol"}},
		{"no members", "empty", []string{""}},
		{"a group that is not there", "absent", nil},
		{"a line with too few fields is skipped", "short", nil},
		{"the group name is not matched against another field", "900", nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := groupMembers(tc.group); !slices.Equal(got, tc.want) {
				t.Errorf("groupMembers(%q) = %q, want %q", tc.group, got, tc.want)
			}
		})
	}
}

func TestGroupMembersOnAnUnreadableFile(t *testing.T) {
	original := groupFile
	groupFile = filepath.Join(t.TempDir(), "absent")
	t.Cleanup(func() { groupFile = original })
	if got := groupMembers("faramir"); got != nil {
		t.Errorf("an unreadable group file returned %q, want nothing", got)
	}
}

// Allowed's short-circuits, which decide before either name is consulted. Named
// accounts and groups that do not resolve are checks that do not pass, not
// checks that are skipped.
func TestAllowedDecidesOnUidBeforeConsultingAnyName(t *testing.T) {
	useGroupFile(t, groupFixture)
	self := int32(os.Getuid())
	// A uid that is neither root nor this process's, so no short-circuit applies.
	stranger := int32(60999)
	if stranger == self {
		stranger = 60998
	}
	for _, tc := range []struct {
		name    string
		peer    *Peer
		account string
		group   string
		want    bool
	}{
		{"root is always allowed", &Peer{UID: 0, GID: 0}, "", "", true},
		{"root is allowed even naming nothing it matches", &Peer{UID: 0}, "nosuch", "nosuch", true},
		{"our own uid is allowed", &Peer{UID: self}, "", "", true},
		{"a stranger with no names is refused", &Peer{UID: stranger, GID: 65500}, "", "", false},
		{"a stranger naming accounts that do not exist is refused",
			&Peer{UID: stranger, GID: 65500}, "nosuchuser", "nosuchgroup", false},
		{"an empty name is not a check that passes",
			&Peer{UID: stranger, GID: 65500}, "", "faramir", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Allowed(tc.peer, tc.account, tc.group); got != tc.want {
				t.Errorf("Allowed(uid=%d, %q, %q) = %v, want %v",
					tc.peer.UID, tc.account, tc.group, got, tc.want)
			}
		})
	}
}

// AllowedUser is the two internal sockets' check, and each admits exactly one
// account. Naming a group here would widen them to everyone in it.
//
// The peer carries a gid that a real group resolves to, so that consulting any
// group at all would admit it on the gid path. A gid matching nothing on this
// host would make the check pass whether or not a group was consulted.
func TestAllowedUserConsultsNoGroup(t *testing.T) {
	useGroupFile(t, groupFixture)
	self, err := user.Current()
	if err != nil {
		t.Fatalf("no current user: %v", err)
	}
	gid, err := strconv.Atoi(self.Gid)
	if err != nil {
		t.Fatal(err)
	}
	stranger := int32(60999)
	if stranger == int32(os.Getuid()) {
		stranger = 60998
	}
	peer := &Peer{UID: stranger, GID: int32(gid)}

	// The same peer with that group named is admitted, which is what makes the
	// refusal below evidence that no group was consulted.
	if group, err := user.LookupGroupId(self.Gid); err == nil {
		if !Allowed(peer, "nosuchuser", group.Name) {
			t.Fatalf("the fixture is wrong: %s does not admit a peer on its gid", group.Name)
		}
	}
	if AllowedUser(peer, "nosuchuser") {
		t.Error("AllowedUser admitted a peer on a group's gid, so it consulted a group")
	}
	if !AllowedUser(&Peer{UID: 0}, "nosuchuser") {
		t.Error("AllowedUser refused root")
	}
}
