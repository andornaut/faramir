// Package keeperclient talks to the keeper socket.
//
// It is deliberately separate from the keeper itself, which is the server on
// the other end of the same socket.  What the split buys is not a smaller
// binary, since there is one binary and it carries both: it is that the broker
// reaches values only by asking over a socket, in code that has no access to the
// key, the sops invocation, or the decrypted set the keeper holds.
package keeperclient

import (
	"encoding/json"
	"fmt"
	"net"

	"github.com/andornaut/faramir/internal/sockutil"
)

// Error means the keeper could not be reached, or refused the request.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

// FetchValues asks the keeper for the decrypted value set.
//
// Every value, not a subset: the redactor is built from the whole set, because
// a managed host can print a credential this command never injected.
//
// A per-file decryption failure comes back in the errors slice instead of as
// an error, so one broken file does not blank the whole value set.
func FetchValues(socketPath string) (map[string]string, []string, error) {
	request := map[string]any{"op": "get_values"}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, nil, errf("keeper socket %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := sockutil.Send(conn, request); err != nil {
		return nil, nil, errf("keeper: %v", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<24)
	if err != nil {
		return nil, nil, errf("keeper: %v", err)
	}
	if len(line) == 0 {
		return nil, nil, errf("keeper closed the connection without responding")
	}

	var response struct {
		Values map[string]string `json:"values"`
		Errors []string          `json:"errors"`
		Error  *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return nil, nil, errf("malformed response from keeper: %v", err)
	}
	if response.Error != nil {
		return nil, nil, errf("keeper: %s: %s", response.Error.Code, response.Error.Message)
	}
	if response.Values == nil {
		return nil, nil, errf("keeper response has no 'values' object")
	}
	return response.Values, response.Errors, nil
}
