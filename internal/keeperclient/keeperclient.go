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

// FileState is one managed file's fingerprint, as the keeper reports it.
//
// Comparable, because the broker's staleness check is set equality over these
// and nothing else.  It carries no contents: what the broker learns from a
// change is that it must reload, never anything about what changed.
type FileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// response is every field either op can return.  One shape for both, because
// the ops differ in which fields they fill rather than in the envelope, and a
// struct per op would be two decode paths that have to agree about errors.
type response struct {
	Values map[string]string `json:"values"`
	State  []FileState       `json:"state"`
	Errors []string          `json:"errors"`
	Error  *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call sends one request and decodes the reply.
func call(socketPath, op string) (*response, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, errf("keeper socket %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := sockutil.Send(conn, map[string]any{"op": op}); err != nil {
		return nil, errf("keeper: %v", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<24)
	if err != nil {
		return nil, errf("keeper: %v", err)
	}
	if len(line) == 0 {
		return nil, errf("keeper closed the connection without responding")
	}

	var out response
	if err := json.Unmarshal(line, &out); err != nil {
		return nil, errf("malformed response from keeper: %v", err)
	}
	if out.Error != nil {
		return nil, errf("keeper: %s: %s", out.Error.Code, out.Error.Message)
	}
	return &out, nil
}

// FetchValues asks the keeper for the decrypted value set, and for the
// fingerprints of the files it decrypted.
//
// Every value, not a subset: the redactor is built from the whole set, because
// a managed host can print a credential this command never injected.
//
// The state comes back with the values rather than from a second call, so the
// two describe the same moment: a fingerprint fetched separately could be of a
// file edited after the decrypt, and the change would then never be noticed.
//
// A per-file decryption failure comes back in the errors slice instead of as
// an error, so one broken file does not blank the whole value set.
func FetchValues(socketPath string) (map[string]string, []FileState, []string, error) {
	out, err := call(socketPath, "get_values")
	if err != nil {
		return nil, nil, nil, err
	}
	if out.Values == nil {
		return nil, nil, nil, errf("keeper response has no 'values' object")
	}
	return out.Values, out.State, out.Errors, nil
}

// FetchState asks the keeper which managed files exist and when they changed.
//
// The cheap call: no key, no sops, no contents, so it is the one the broker
// makes on a poll.  The broker cannot stat these itself, the store being
// readable by the keeper's group alone.
//
// A file the keeper could not stat is reported in the errors slice and absent
// from the state, which makes it a change like any other and reloads.
func FetchState(socketPath string) ([]FileState, []string, error) {
	out, err := call(socketPath, "get_state")
	if err != nil {
		return nil, nil, err
	}
	return out.State, out.Errors, nil
}
