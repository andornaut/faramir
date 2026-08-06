// Package sockutil holds the socket plumbing the three daemons share:
// systemd activation, SO_PEERCRED authorisation, sd_notify, and the
// newline-delimited JSON framing.
package sockutil

import (
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

	"golang.org/x/sys/unix"
)

// listenFDStart is systemd's SD_LISTEN_FDS_START.
const listenFDStart = 3

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

// AllowedByUsersOrGroups is the authorisation the two internal sockets use.
//
// Our own uid covers the single-uid test harness; root is unavoidable.
func AllowedByUsersOrGroups(peer *Peer, users, groups []string) bool {
	if peer.UID == 0 || int(peer.UID) == os.Getuid() {
		return true
	}
	for _, name := range users {
		if u, err := user.Lookup(name); err == nil {
			if uid, err := strconv.Atoi(u.Uid); err == nil && int32(uid) == peer.UID {
				return true
			}
		}
	}
	for _, name := range groups {
		if g, err := user.LookupGroup(name); err == nil {
			if gid, err := strconv.Atoi(g.Gid); err == nil && int32(gid) == peer.GID {
				return true
			}
		}
	}
	log.Printf("rejected connection from uid=%d gid=%d pid=%d", peer.UID, peer.GID, peer.PID)
	return false
}

// ReadLine reads one newline-terminated JSON payload, up to limit bytes.
// It returns nil with no error when the peer sent nothing usable.
func ReadLine(conn net.Conn, limit int) ([]byte, error) {
	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 65536)
	for {
		if idx := indexByte(buf, '\n'); idx >= 0 {
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
	if idx := indexByte(buf, '\n'); idx >= 0 {
		return buf[:idx], nil
	}
	if len(trimSpace(buf)) == 0 {
		return nil, nil
	}
	return buf, nil
}

var ErrTooLarge = errors.New("request too large")

func indexByte(b []byte, c byte) int {
	for i, x := range b {
		if x == c {
			return i
		}
	}
	return -1
}

func trimSpace(b []byte) []byte {
	start := 0
	for start < len(b) && (b[start] == ' ' || b[start] == '\t' || b[start] == '\n' || b[start] == '\r') {
		start++
	}
	end := len(b)
	for end > start && (b[end-1] == ' ' || b[end-1] == '\t' || b[end-1] == '\n' || b[end-1] == '\r') {
		end--
	}
	return b[start:end]
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
	conn, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer conn.Close()
	_, _ = conn.Write([]byte("READY=1"))
}
