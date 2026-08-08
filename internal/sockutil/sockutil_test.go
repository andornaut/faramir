package sockutil

import (
	"os"
	"os/user"
	"strconv"
	"testing"
)

func TestAnUnlistedPeerIsRejected(t *testing.T) {
	peer := &Peer{UID: unusedUID(t), GID: 65500}
	if Allowed(peer, nil, nil, nil) {
		t.Error("an unlisted peer was allowed")
	}
	if Allowed(peer, []int{4242}, []string{"nosuchuser"}, []string{"nosuchgroup"}) {
		t.Error("a peer matching none of the lists was allowed")
	}
}

func TestAListedUIDIsAllowed(t *testing.T) {
	uid := unusedUID(t)
	if !Allowed(&Peer{UID: uid, GID: 65500}, []int{int(uid)}, nil, nil) {
		t.Error("a uid on allowed_uids was rejected")
	}
}

// The group a peer is in is usually a *supplementary* one -- dev is
// granted with usermod -aG, so it is never the primary gid.  Checking only the
// gid would make every allowed_groups entry silently ineffective.
func TestSupplementaryGroupMembershipIsHonoured(t *testing.T) {
	self, err := user.Current()
	if err != nil {
		t.Skipf("no current user: %v", err)
	}
	gids, err := self.GroupIds()
	if err != nil {
		t.Skipf("cannot read our groups: %v", err)
	}
	primary := self.Gid

	var group string
	for _, gid := range gids {
		if gid == primary {
			continue
		}
		if g, err := user.LookupGroupId(gid); err == nil {
			// Only a group we are in by name in /etc/group proves the point;
			// the gid path is already covered by the primary-gid check.
			for _, member := range groupMembers(g.Name) {
				if member == self.Username {
					group = g.Name
				}
			}
		}
	}
	if group == "" {
		t.Skip("this user has no supplementary group listed in /etc/group")
	}

	// A gid that is deliberately not ours, so only the member list can match.
	uid, _ := strconv.Atoi(self.Uid)
	peer := &Peer{UID: int32(uid), GID: 65500}
	if os.Getuid() == uid {
		// Allowed short-circuits on our own uid, so exercise the group check
		// directly rather than through it.
		if !inAnyGroup(peer, []string{group}) {
			t.Errorf("supplementary membership of %s was not honoured", group)
		}
		return
	}
	if !Allowed(peer, nil, nil, []string{group}) {
		t.Errorf("supplementary membership of %s was not honoured", group)
	}
}

// unusedUID returns a uid that is neither root nor ours, so the
// short-circuits in Allowed do not decide the test for us.
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
