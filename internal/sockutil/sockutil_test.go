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

// the request cap bounds what an unauthenticated read allocates.
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

// -- reading a stream of payloads -------------------------------------------

// LineReader keeps whatever a read pulled in past the newline, so successive
// payloads all arrive. ReadLine keeps no buffer and drops it, which is why a
// stream uses this rather than calling ReadLine twice.
func TestALineReaderReturnsEveryPayload(t *testing.T) {
	reader := NewLineReader(pipeWriting(t, "first\nsecond\nthird\n"), 64)
	for _, want := range []string{"first", "second", "third"} {
		line, err := reader.Next()
		if err != nil {
			t.Fatalf("reading %q: %v", want, err)
		}
		if string(line) != want {
			t.Errorf("payload = %q, want %q", line, want)
		}
	}
}

// The same contract ReadLine has at the edges, so the broker answers a stream's
// chunks and a lone request identically.
func TestALineReaderKeepsReadLinesContract(t *testing.T) {
	if _, err := NewLineReader(pipeWriting(t, strings.Repeat("x", 200)+"\n"), 64).Next(); !errors.Is(err, ErrTooLarge) {
		t.Errorf("a payload over the limit: err = %v, want ErrTooLarge", err)
	}
	// The CLI closes its write half rather than terminating the last line.
	line, err := NewLineReader(pipeWriting(t, `{"op":"status"}`), 64).Next()
	if err != nil || string(line) != `{"op":"status"}` {
		t.Errorf("a payload ended by EOF: %q, %v", line, err)
	}
	// A peer that sends only whitespace and closes is nothing usable: nil and no
	// error, rather than an empty payload for the caller to try to parse.
	if line, err := NewLineReader(pipeWriting(t, "   "), 64).Next(); err != nil || line != nil {
		t.Errorf("whitespace then EOF: %q, %v", line, err)
	}
}

// A payload longer than the buffer arrives in pieces and must be rejoined.
func TestALineReaderRejoinsAPayloadLongerThanItsBuffer(t *testing.T) {
	body := strings.Repeat("y", 40000)
	reader := NewLineReader(pipeWriting(t, body+"\nnext\n"), 1<<20)
	line, err := reader.Next()
	if err != nil {
		t.Fatal(err)
	}
	if string(line) != body {
		t.Errorf("payload is %d bytes, want %d", len(line), len(body))
	}
	if line, err = reader.Next(); err != nil || string(line) != "next" {
		t.Errorf("the payload after a long one = %q, %v", line, err)
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
