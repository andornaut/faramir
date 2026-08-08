// Package sockutil holds the socket plumbing the three daemons share:
// systemd activation, SO_PEERCRED authorisation, sd_notify, and the
// newline-delimited JSON framing.
package sockutil

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/user"
	"path/filepath"
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

// RetryAccept reports whether an Accept error is one to sleep on and retry,
// and how long to sleep, given the previous delay.
//
// A loop that returns on any error leaves the socket bound and accepting
// nothing: a client's connect lands in the backlog and waits for its own
// timeout instead of failing, and a unit that returns nil exits 0, which
// Restart=on-failure does not restart.  Running out of descriptors or memory,
// and a peer that goes away between its connect and our accept, are all
// recoverable.  Anything else means the listener itself is gone.
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

// Listen uses the systemd-passed socket if present, else binds its own.
func Listen(path string, mode os.FileMode) (net.Listener, error) {
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
		// FileListener dups the descriptor; the original is ours to drop.
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
	// Bind under a umask that yields the requested mode, then chmod: a socket
	// created world-writable and narrowed afterwards is reachable in between.
	previous := unix.Umask(0o777 &^ int(mode))
	ln, err := net.Listen("unix", path)
	unix.Umask(previous)
	if err != nil {
		return nil, err
	}
	if err := os.Chmod(path, mode); err != nil {
		_ = ln.Close()
		return nil, err
	}
	// Go removes the socket file on Close by default.  That is what we want
	// for a self-bound socket and wrong for an activated one, which systemd
	// owns; the activated branch above returns before this.
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

// Allowed is the authorisation every faramir socket uses.
//
// Our own uid covers the single-uid test harness; root is unavoidable.  A uid
// listed in uids, a user named in users, or membership of a group in groups --
// primary or supplementary -- is what else passes.
func Allowed(peer *Peer, uids []int, users, groups []string) bool {
	if peer.UID == 0 || int(peer.UID) == os.Getuid() {
		return true
	}
	for _, uid := range uids {
		if int32(uid) == peer.UID {
			return true
		}
	}
	for _, name := range users {
		if u, err := user.Lookup(name); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil && int32(uid) == peer.UID {
				return true
			}
		}
	}
	if len(groups) > 0 && inAnyGroup(peer, groups) {
		return true
	}
	log.Printf("rejected connection from uid=%d gid=%d pid=%d", peer.UID, peer.GID, peer.PID)
	return false
}

// AllowedUser is Allowed with neither a uid list nor groups, for the two
// internal sockets: each has exactly one legitimate client, and names it.
//
// No group form.  The only group in play is dev, which holds the agent's
// own uid, so on these sockets the one value it could take is the one that
// must never be set.
func AllowedUser(peer *Peer, users []string) bool {
	return Allowed(peer, nil, users, nil)
}

// inAnyGroup checks the peer's primary gid and, failing that, the
// supplementary member lists.  Checking only the gid would silently ignore
// every allowed_groups entry that is a secondary group, which is how the
// dev group is actually granted.
func inAnyGroup(peer *Peer, groups []string) bool {
	name := ""
	if u, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		name = u.Username
	}
	for _, group := range groups {
		g, err := user.LookupGroup(group)
		if err != nil {
			continue
		}
		if gid, err := strconv.Atoi(g.Gid); err == nil && int32(gid) == peer.GID {
			return true
		}
		if name == "" {
			continue
		}
		for _, member := range groupMembers(group) {
			if member == name {
				return true
			}
		}
	}
	return false
}

// groupMembers reads the supplementary member list for a group.  Go's os/user
// exposes no equivalent of getgrnam()'s gr_mem.
func groupMembers(name string) []string {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[0] == name {
			return strings.Split(fields[3], ",")
		}
	}
	return nil
}

// ReadLine reads one newline-terminated JSON payload, up to limit bytes.
// It returns nil with no error when the peer sent nothing usable.
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
	if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
		return buf[:idx], nil
	}
	if len(bytes.TrimSpace(buf)) == 0 {
		return nil, nil
	}
	return buf, nil
}

var ErrTooLarge = errors.New("request too large")

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
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("READY=1"))
}
