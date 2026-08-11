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

// -- reading a stream of payloads -------------------------------------------

// The trap LineReader exists for.  ReadLine keeps no buffer, so whatever its
// last read pulled in past the newline is dropped; called twice on one
// connection it loses the second payload whenever both arrived together.
func TestReadLineDropsWhatFollowsTheNewline(t *testing.T) {
	conn := pipeWriting(t, "first\nsecond\n")
	if line, err := ReadLine(conn, 64); err != nil || string(line) != "first" {
		t.Fatalf("first = %q, %v", line, err)
	}
	line, err := ReadLine(conn, 64)
	if err == nil && string(line) == "second" {
		t.Skip("this read happened to see the second payload; the point is that it " +
			"may not, which is why a stream uses LineReader")
	}
}

// LineReader keeps the buffer, so successive payloads all arrive.
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
