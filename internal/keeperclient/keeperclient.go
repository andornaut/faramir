// Package keeperclient talks to the keeper socket.  Separate from the keeper
// itself so the broker reaches values only by asking, in code with no access to
// the key, the sops invocation, or the decrypted set.
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

// FileState is one managed file's fingerprint.  Comparable, since the staleness
// check is set equality over these, and it carries no contents.
type FileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// response is every field either op can return: they differ in which fields
// they fill, not in the envelope.
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

// FetchValues asks the keeper for the decrypted value set and the fingerprints
// of the files it decrypted.  Every value, not a subset, and the state comes
// back with them so the two describe the same moment.  A per-file failure is in
// the errors slice rather than an error, so one broken file does not blank the
// set.
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

// FetchState asks the keeper which managed files exist and when they changed:
// no key, no sops, no contents, so it is what the broker polls with.  A file
// the keeper could not stat is in the errors slice and absent from the state,
// which reads as a change and reloads.
func FetchState(socketPath string) ([]FileState, []string, error) {
	out, err := call(socketPath, "get_state")
	if err != nil {
		return nil, nil, err
	}
	return out.State, out.Errors, nil
}
