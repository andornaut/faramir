package main

import (
	"context"
	"encoding/json"
	"net"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// tellBrokerToReRead asks the running broker to re-read the managed store now,
// and reports whether it did.
//
// Called by the commands that write the store. Without it a value stays outside
// the redactor until the refresh interval comes round, and a command run in
// that window prints it in the clear, which is what an operator does
// immediately after rotating one to see that it took.
//
// Not fatal when it does not land: the file is written either way, and a broker
// that is not running, is mid-restart, or is an older build that does not know
// the op is not a reason to call the write a failure. It is not silent either.
// The caller says what happened, because "the broker has re-read it" on a host
// where nothing answered is the sentence that sends somebody to run the command
// this exists to make safe.
func tellBrokerToReRead() bool {
	conn, err := (&net.Dialer{Timeout: refreshDialWait}).DialContext(
		context.Background(), "unix", socketDefault())
	if err != nil {
		return false
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(refreshWait))
	if err := sockutil.Send(conn, map[string]any{
		"op": "refresh", "version": version.Version}); err != nil {
		return false
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	// Read the answer rather than closing on it: the refresh runs while the
	// broker is answering, so returning before it lands would leave the same
	// window this exists to close, just a shorter one. And the answer is what
	// says it landed: an older broker refuses the op it does not know.
	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil || len(line) == 0 {
		return false
	}
	var reply struct {
		Error *struct {
			Code string `json:"code"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		return false
	}
	return reply.Error == nil
}

// reReadNote is what a command that wrote the store says about the broker,
// which depends on whether it answered.
func reReadNote(reread bool) string {
	if reread {
		return "the broker has re-read it"
	}
	return "the broker did not answer, so it picks this up within one refresh interval"
}

const (
	// refreshDialWait is short: a broker that is not there is the ordinary case
	// on a host being provisioned, and this must not make `vault add` feel slow.
	refreshDialWait = 2 * time.Second
	// refreshWait covers one decrypt of the whole store, which is what the
	// broker does before it answers.
	refreshWait = 2 * time.Minute
)
