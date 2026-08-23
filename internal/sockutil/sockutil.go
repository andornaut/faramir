// Package sockutil holds the socket plumbing the three daemons share: systemd
// activation, SO_PEERCRED authorisation, sd_notify, and the newline-delimited
// JSON framing.
package sockutil

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// listenFDStart is systemd's SD_LISTEN_FDS_START.
const listenFDStart = 3

// Bounds on the accept backoff, shared by every listener loop.
const (
	acceptDelayMin = 5 * time.Millisecond
	acceptDelayMax = time.Second
)

// RetryAccept reports whether an Accept error is one to sleep on and retry, and
// for how long. A loop that returned on any error would leave the socket bound
// and accepting nothing, and exit 0, which Restart=on-failure does not restart.
// Descriptor and memory exhaustion, and a peer that goes away before the
// accept, are recoverable; anything else means the listener is gone.
func RetryAccept(err error, delay time.Duration) (time.Duration, bool) {
	for _, errno := range []unix.Errno{
		unix.EMFILE, unix.ENFILE, unix.ENOBUFS, unix.ENOMEM,
		unix.ECONNABORTED, unix.EINTR,
	} {
		if errors.Is(err, errno) {
			return min(max(delay*2, acceptDelayMin), acceptDelayMax), true
		}
	}
	return 0, false
}

// bindMode is the mode a self-bound socket gets. Not configurable: under
// systemd the .socket unit's SocketMode= decides and this path is never
// reached, so a config key would describe a socket rather than choose one.
const bindMode = 0o660

// Listen uses the systemd-passed socket if present, else binds its own.
func Listen(path string) (net.Listener, error) {
	fds, _ := strconv.Atoi(os.Getenv("LISTEN_FDS"))
	listenPID, _ := strconv.Atoi(os.Getenv("LISTEN_PID"))
	if fds > 0 && listenPID == os.Getpid() {
		if fds != 1 {
			return nil, fmt.Errorf("expected exactly 1 socket from systemd, got %d", fds)
		}
		f := os.NewFile(listenFDStart, "systemd-socket")
		ln, err := net.FileListener(f)
		if err != nil {
			return nil, fmt.Errorf("socket activation fd %d: %w", listenFDStart, err)
		}
		// FileListener dups the descriptor.
		_ = f.Close()
		log.Printf("using socket activation fd %d", listenFDStart)
		return ln, nil
	}

	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	if _, err := os.Lstat(path); err == nil {
		if err := os.Remove(path); err != nil {
			return nil, err
		}
	}
	// Bind under a umask that yields bindMode: a socket created world-writable
	// and narrowed afterwards is reachable in between. ListenConfig with a
	// background context, a unix bind resolving nothing and connecting to
	// nothing.
	previous := unix.Umask(0o777 &^ int(bindMode))
	ln, err := (&net.ListenConfig{}).Listen(context.Background(), "unix", path)
	unix.Umask(previous)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, bindMode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	// Go unlinks on Close, which is right for a self-bound socket and wrong for
	// an activated one; that branch returns above.
	log.Printf("listening on %s", path)
	return ln, nil
}

// Peer is the credentials of a connected client.
type Peer struct {
	PID int32 `json:"pid"`
	UID int32 `json:"uid"`
	GID int32 `json:"gid"`
}

// PeerCred reads SO_PEERCRED from a Unix connection.
func PeerCred(conn net.Conn) (*Peer, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, errors.New("not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return nil, err
	}
	var cred *unix.Ucred
	var credErr error
	if err := raw.Control(func(fd uintptr) {
		cred, credErr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED)
	}); err != nil {
		return nil, err
	}
	if credErr != nil {
		return nil, credErr
	}
	return &Peer{PID: cred.Pid, UID: int32(cred.Uid), GID: int32(cred.Gid)}, nil
}

// Allowed is the authorisation every faramir socket uses: this process's own
// uid, root, the named account, or membership of the named group. Either name
// may be empty, which is a check that does not apply rather than one that
// passes. One of each, every socket here admitting one account or one group.
//
// Accounts are named, never numbered: a uid stops matching once a reinstall
// renumbers the account.
func Allowed(peer *Peer, account, group string) bool {
	if peer.UID == 0 || int(peer.UID) == os.Getuid() {
		return true
	}
	if account != "" {
		if u, err := user.Lookup(account); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil && int32(uid) == peer.UID {
				return true
			}
		}
	}
	if group != "" && inGroup(peer, group) {
		return true
	}
	log.Printf("rejected connection from uid=%d gid=%d pid=%d", peer.UID, peer.GID, peer.PID)
	return false
}

// AllowedUser is Allowed without a group, for the two internal sockets: each
// has exactly one legitimate client and names it.
func AllowedUser(peer *Peer, account string) bool {
	return Allowed(peer, account, "")
}

// inGroup checks the peer's primary gid, then the supplementary member list,
// which is how allowed_group is usually granted.
func inGroup(peer *Peer, group string) bool {
	g, err := user.LookupGroup(group)
	if err != nil {
		return false
	}
	if gid, err := strconv.Atoi(g.Gid); err == nil && int32(gid) == peer.GID {
		return true
	}
	name := ""
	if u, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		name = u.Username
	}
	if name == "" {
		return false
	}
	return slices.Contains(groupMembers(group), name)
}

// groupFile is the member list's source, a variable so a test can supply one
// rather than depend on the accounts the host happens to have.
var groupFile = "/etc/group"

// groupMembers reads a group's supplementary members; os/user exposes no
// equivalent of getgrnam()'s gr_mem.
func groupMembers(name string) []string {
	data, err := os.ReadFile(groupFile)
	if err != nil {
		return nil
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[0] == name {
			return strings.Split(fields[3], ",")
		}
	}
	return nil
}

// ReadLine reads one newline-terminated JSON payload, up to limit bytes. It
// returns nil with no error when the peer sent nothing usable.
func ReadLine(conn net.Conn, limit int) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 65536)
	for {
		if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
			return buf[:idx], nil
		}
		n, err := conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if len(buf) > limit {
				return nil, ErrTooLarge
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
	}
	if before, _, ok := bytes.Cut(buf, []byte{'\n'}); ok {
		return before, nil
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, nil
	}
	return buf, nil
}

// ErrTooLarge is a payload past the reader's limit, in either direction: the
// same reader takes a request on a daemon's side and a reply on a client's, so
// the sentinel names neither and the caller says which it was reading.
var ErrTooLarge = errors.New("payload exceeds the size limit")

// LineReader reads successive payloads from one connection. ReadLine discards
// whatever its last read pulled in past the newline, which for a stream is the
// start of the next payload; keeping the buffer here is what lets a second call
// see it.
type LineReader struct {
	reader *bufio.Reader
	limit  int
}

func NewLineReader(conn net.Conn, limit int) *LineReader {
	return &LineReader{reader: bufio.NewReader(conn), limit: limit}
}

// Next reads one payload, with ReadLine's contract: nil and no error when the
// peer sent nothing usable, ErrTooLarge past the limit.
func (lr *LineReader) Next() ([]byte, error) {
	var buf []byte
	for {
		// ReadSlice returns what it has with ErrBufferFull when the payload is
		// longer than the buffer, so a long one arrives in pieces.
		chunk, err := lr.reader.ReadSlice('\n')
		if len(chunk) > 0 {
			buf = append(buf, chunk...)
			if len(buf) > lr.limit {
				return nil, ErrTooLarge
			}
		}
		if errors.Is(err, bufio.ErrBufferFull) {
			continue
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		return buf[:len(buf)-1], nil // ReadSlice keeps the delimiter
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, nil
	}
	return buf, nil
}

// Send writes one JSON response followed by a newline.
func Send(conn net.Conn, response any) error {
	data, err := json.Marshal(response)
	if err != nil {
		return err
	}
	_, err = conn.Write(append(data, '\n'))
	return err
}

// NotifyReady sends sd_notify(READY=1) so systemd knows the socket is served.
func NotifyReady() {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	if addr[0] == '@' {
		addr = "\x00" + addr[1:]
	}
	// A datagram socket, so this connects to nothing and cannot block; the
	// context is what the dial takes rather than a deadline on anything.
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unixgram", addr)
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_, _ = conn.Write([]byte("READY=1"))
}
