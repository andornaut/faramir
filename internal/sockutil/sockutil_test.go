package sockutil

import (
	"errors"
	"net"
	"os"
	"os/user"
	"strconv"
	"strings"
	"testing"
)

// -- the request limit ------------------------------------------------------

// pipeWriting returns the reading end of a pipe with body already on its way.
func pipeWriting(t *testing.T, body string) net.Conn {
	t.Helper()
	writer, reader := net.Pipe()
	t.Cleanup(func() { _ = reader.Close(); _ = writer.Close() })
	go func() {
		_, _ = writer.Write([]byte(body))
		_ = writer.Close()
	}()
	return reader
}

// [server] max_request_bytes bounds what an unauthenticated read allocates.
// ErrTooLarge rather than a short line: the broker answers with too_large,
// where a truncated line would parse as a malformed request.
func TestReadLineRefusesALineOverTheLimit(t *testing.T) {
	_, err := ReadLine(pipeWriting(t, strings.Repeat("x", 200)+"\n"), 64)
	if !errors.Is(err, ErrTooLarge) {
		t.Errorf("err = %v, want ErrTooLarge", err)
	}
}

func TestReadLineReturnsALineInsideTheLimit(t *testing.T) {
	line, err := ReadLine(pipeWriting(t, "{\"op\":\"status\"}\nsecond line\n"), 64)
	if err != nil {
		t.Fatal(err)
	}
	// The first line only, without its newline.
	if string(line) != `{"op":"status"}` {
		t.Errorf("line = %q", line)
	}
}

// The CLI closes its write half rather than terminating the line, so refusing
// this would refuse every call it makes.
func TestReadLineAcceptsALineEndedByEOF(t *testing.T) {
	line, err := ReadLine(pipeWriting(t, `{"op":"status"}`), 64)
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != `{"op":"status"}` {
		t.Errorf("line = %q", line)
	}
}

// -- peer authorization -----------------------------------------------------

func TestAnUnlistedPeerIsRejected(t *testing.T) {
	peer := &Peer{UID: unusedUID(t), GID: 65500}
	if Allowed(peer, "", "") {
		t.Error("an unlisted peer was allowed")
	}
	if Allowed(peer, "nosuchuser", "nosuchgroup") {
		t.Error("a peer matching neither name was allowed")
	}
}

// allowed_user names an account, and the uid is looked up from the name.  This
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
	for _, line := range strings.Split(string(body), "\n") {
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

// The group is usually a supplementary one, granted with usermod -aG, so
// checking the gid alone would make allowed_group ineffective.
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
			// A group we are in by name; the gid path is covered above.
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

	// Not our gid, so only the member list can match.
	uid, _ := strconv.Atoi(self.Uid)
	peer := &Peer{UID: int32(uid), GID: 65500}
	if os.Getuid() == uid {
		// Allowed short-circuits on our own uid.
		if !inGroup(peer, group) {
			t.Errorf("supplementary membership of %s was not honoured", group)
		}
		return
	}
	if !Allowed(peer, "", group) {
		t.Errorf("supplementary membership of %s was not honoured", group)
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
