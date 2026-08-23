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
func tellBrokerToReRead() string {
	conn, err := (&net.Dialer{Timeout: refreshDialWait}).DialContext(
		context.Background(), "unix", socketDefault())
	if err != nil {
		return ""
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(refreshWait))
	if err := sockutil.Send(conn, map[string]any{
		"op": "refresh", "version": version.Version}); err != nil {
		return ""
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
		return ""
	}
	var reply struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &reply); err != nil {
		return ""
	}
	if reply.Error != nil {
		// A broker that answered and said no. The commonest is version skew, the
		// binary having been replaced before the daemon was restarted, and
		// reporting that as silence sends an operator to look at a daemon that is
		// answering.
		return reply.Error.Message
	}
	return reReadOK
}

// reReadOK is what tellBrokerToReRead returns when the broker re-read the
// store: a sentinel rather than a bool, so the refusals it can answer with are
// carried back with it.
const reReadOK = "ok"

// reReadNote is what a command that wrote the store says about the broker. It
// stands next to "wrote the file", so it has to say whether the value is
// covered yet rather than leaving that to be assumed.
func reReadNote(answer, waiting string) string {
	switch answer {
	case reReadOK:
		return "the broker has re-read it"
	case "":
		return "the broker did not answer, so " + waiting
	}
	return "the broker refused to re-read it (" + answer + "), so " + waiting
}

const (
	// refreshDialWait is short: a broker that is not there is the ordinary case
	// on a host being provisioned, and this must not make `vault add` feel slow.
	refreshDialWait = 2 * time.Second
	// refreshWait covers one decrypt of the whole store, which is what the
	// broker does before it answers.
	refreshWait = 2 * time.Minute
)
