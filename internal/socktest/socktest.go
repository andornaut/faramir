// Package socktest stands in for a daemon on a socket. Imported only from
// _test.go files.
package socktest

import (
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/sockutil"
)

// AnsweringBroker answers every request with reply on a socket of its own and
// hands back the path. A nil reply closes the connection without answering,
// which is the broker restarting under the request rather than refusing it.
func AnsweringBroker(t *testing.T, reply any) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := sockutil.ReadLine(conn, 1<<20); err != nil {
					return
				}
				if reply == nil {
					return
				}
				_ = sockutil.Send(conn, reply)
			}()
		}
	}()
	return socketPath
}
