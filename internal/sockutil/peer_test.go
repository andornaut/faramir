package sockutil

// Peer authorization.

import (
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

func TestAnUnlistedPeerIsRejected(t *testing.T) {
	peer := &Peer{UID: unusedUID(t), GID: 65500}
	if Allowed(peer, "", "") {
		t.Error("an unlisted peer was allowed")
	}
	if Allowed(peer, "nosuchuser", "nosuchgroup") {
		t.Error("a peer matching neither name was allowed")
	}
}

// allowed_user names an account, and the uid is looked up from the name. This
// is the only spelling left: allowed_uids said the same thing in numbers, which
// stopped being true the moment an account was renumbered.
func TestAListedUserIsAllowed(t *testing.T) {
	name, uid := otherAccount(t)
	if !Allowed(&Peer{UID: uid, GID: 65500}, name, "") {
		t.Errorf("%s, on allowed_user, was rejected", name)
	}
	// The name is not a password: a peer that is not the account it names is still
	// refused, so the lookup has to be what decides.
	if Allowed(&Peer{UID: unusedUID(t), GID: 65500}, name, "") {
		t.Errorf("a peer whose uid is not %s's was allowed", name)
	}
}

// otherAccount finds a real account that is neither root nor ours, both of
// which Allowed short-circuits on before it reaches the user list.
func otherAccount(t *testing.T) (string, int32) {
	t.Helper()
	body, err := os.ReadFile("/etc/passwd")
	if err != nil {
		t.Skipf("cannot read /etc/passwd: %v", err)
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) < 3 {
			continue
		}
		uid, err := strconv.Atoi(fields[2])
		if err != nil || uid == 0 || uid == os.Getuid() {
			continue
		}
		// Looked up by name, because that is the call Allowed makes: an entry this
		// process cannot resolve would fail the test for the wrong reason.
		if _, err := user.Lookup(fields[0]); err == nil {
			return fields[0], int32(uid)
		}
	}
	t.Skip("no account here is both resolvable and neither root nor us")
	return "", 0
}

// allowed_group is usually granted with usermod -aG, so a check on the gid
// alone would make it ineffective. Both paths are driven here against a written
// group file: the group is a real one so user.LookupGroup resolves it, and the
// member list is this test's. Hunting the host for a group that already has the
// right shape makes a broken groupMembers skip the test rather than fail it.
func TestInGroupHonoursBothTheGidAndTheMemberList(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Fatalf("no current user: %v", err)
	}
	group, err := user.LookupGroupId(self.Gid)
	if err != nil {
		t.Fatalf("this user's primary group does not resolve: %v", err)
	}
	gid, err := strconv.Atoi(self.Gid)
	if err != nil {
		t.Fatal(err)
	}
	uid, err := strconv.Atoi(self.Uid)
	if err != nil {
		t.Fatal(err)
	}
	// Not the group's gid, so only the member list can decide.
	const otherGID = 65500
	if gid == otherGID {
		t.Fatalf("this user's gid is the one the test uses as an outsider's")
	}

	for _, tc := range []struct {
		name    string
		gid     int32
		members string
		want    bool
	}{
		{"the primary gid matches with no member list", int32(gid), "", true},
		{"a listed member matches on another gid", otherGID, self.Username, true},
		{"one of several listed members matches", otherGID, "someone," + self.Username, true},
		{"an unlisted peer on another gid is refused", otherGID, "someone-else", false},
		{"an empty member list on another gid is refused", otherGID, "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			useGroupFile(t, group.Name+":x:"+self.Gid+":"+tc.members+"\n")
			if got := inGroup(&Peer{UID: int32(uid), GID: tc.gid}, group.Name); got != tc.want {
				t.Errorf("inGroup(gid=%d, members=%q) = %v, want %v",
					tc.gid, tc.members, got, tc.want)
			}
		})
	}
}

// unusedUID is neither root nor ours, so Allowed's short-circuits do not decide
// the test.
func unusedUID(t *testing.T) int32 {
	t.Helper()
	for uid := int32(60000); uid < 60100; uid++ {
		if int(uid) == os.Getuid() {
			continue
		}
		if _, err := user.LookupId(strconv.Itoa(int(uid))); err != nil {
			return uid
		}
	}
	t.Skip("no unused uid in the probe range")
	return 0
}
