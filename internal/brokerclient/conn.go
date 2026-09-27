package brokerclient

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// Conn is one connection to the broker, and the one place a request is written
// and its answer read. Every client goes through it so that a transport fault
// is classified the same way whichever command met it: the broker could not be
// reached, did not answer, or went away is an UnavailableError, and exits
// ExitUnavailable; an answer, even one this side refuses to read, is not.
type Conn struct {
	conn  net.Conn
	lines *sockutil.LineReader
}

// Dial reaches the broker socket within wait. limit is the longest reply line
// this connection will read.
func Dial(socketPath string, wait time.Duration, limit int) (*Conn, error) {
	conn, err := (&net.Dialer{Timeout: wait}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, &UnavailableError{fserr.At(socketPath, err)}
	}
	return &Conn{conn: conn, lines: sockutil.NewLineReader(conn, limit)}, nil
}

// Close ends the connection. Only then: the write half stays open for the whole
// of a request, because the broker takes an EOF as the caller having gone and
// kills whatever it was running for it.
func (c *Conn) Close() { _ = c.conn.Close() }

// Exchange writes request, stamped with this client's version, and reads one
// reply line, the whole of it within timeout.
//
// A reply past the limit is the one read failure that is not unavailable: the
// broker answered, and will answer the same way again, so a caller retrying on
// ExitUnavailable would retry for ever.
func (c *Conn) Exchange(request map[string]any, timeout time.Duration) ([]byte, error) {
	request["version"] = version.Version
	_ = c.conn.SetDeadline(time.Now().Add(timeout))
	if err := sockutil.Send(c.conn, request); err != nil {
		return nil, &UnavailableError{fmt.Errorf("writing the request: %w", err)}
	}
	line, err := c.lines.Next()
	switch {
	case errors.Is(err, sockutil.ErrTooLarge):
		return nil, fmt.Errorf("reading the response: %w", err)
	case errors.Is(err, os.ErrDeadlineExceeded):
		// Named apart from a close: the socket is systemd's and listens whether
		// or not a broker is behind it, so this is one that did not come up
		// rather than one that refused.
		return nil, &UnavailableError{fmt.Errorf("no answer from the broker within %s", timeout)}
	case err != nil:
		return nil, &UnavailableError{fmt.Errorf("reading the response: %w", err)}
	case len(line) == 0:
		return nil, &UnavailableError{errors.New("the broker closed the connection without answering")}
	}
	return line, nil
}
