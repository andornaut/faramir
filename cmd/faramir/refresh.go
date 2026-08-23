package main

import (
	"context"
	"net"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// tellBrokerToReRead asks the running broker to re-read the managed store now.
//
// Called by the commands that write it. Without this a value stays outside the
// redactor until the refresh interval comes round, and a command run in that
// window prints it in the clear -- which is what an operator does immediately
// after rotating one, to see that it took.
//
// Best effort, and silent. Every caller has already written the file and said
// so; the broker may not be running, may be mid-restart, or may be an older
// build that does not know the op, and none of those is a reason to report the
// write as having failed. What is lost when it does not land is the interval,
// which is what used to happen every time.
func tellBrokerToReRead() {
	conn, err := (&net.Dialer{Timeout: refreshDialWait}).DialContext(
		context.Background(), "unix", socketDefault())
	if err != nil {
		return
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(refreshWait))
	if err := sockutil.Send(conn, map[string]any{
		"op": "refresh", "version": version.Version}); err != nil {
		return
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	// Read the answer rather than closing on it: the refresh runs while the
	// broker is answering, so returning before it lands would leave the same
	// window this exists to close, just a shorter one.
	_, _ = sockutil.ReadLine(conn, 1<<20)
}

const (
	// refreshDialWait is short: a broker that is not there is the ordinary case
	// on a host being provisioned, and this must not make `vault add` feel slow.
	refreshDialWait = 2 * time.Second
	// refreshWait covers one decrypt of the whole store, which is what the
	// broker does before it answers.
	refreshWait = 2 * time.Minute
)
