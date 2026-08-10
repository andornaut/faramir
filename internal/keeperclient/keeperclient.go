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
	// Unresolved is the entries that named nothing, kept apart from Errors: a
	// secrets directory not written yet is what a first install looks like, and a
	// file that is there and will not open is a value the redactor is missing.
	Unresolved []string `json:"unresolved"`
	Error      *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call sends one request and decodes the reply.
func call(socketPath, op string) (*response, error) {
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("keeper socket %s: %v", socketPath, err)
	}
	defer func() { _ = conn.Close() }()

	if err := sockutil.Send(conn, map[string]any{"op": op}); err != nil {
		return nil, fmt.Errorf("keeper: %v", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<24)
	if err != nil {
		return nil, fmt.Errorf("keeper: %v", err)
	}
	if len(line) == 0 {
		return nil, fmt.Errorf("keeper closed the connection without responding")
	}

	var out response
	if err := json.Unmarshal(line, &out); err != nil {
		return nil, fmt.Errorf("malformed response from keeper: %v", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("keeper: %s: %s", out.Error.Code, out.Error.Message)
	}
	return &out, nil
}

// FetchValues asks the keeper for the decrypted value set and the fingerprints
// of the files it decrypted.  Every value, not a subset, and the state comes
// back with them so the two describe the same moment.  A per-file failure is in
// the errors slice rather than an error, so one broken file does not blank the
// set.
func FetchValues(socketPath string) (map[string]string, []FileState, []string, []string, error) {
	out, err := call(socketPath, "get_values")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if out.Values == nil {
		return nil, nil, nil, nil, fmt.Errorf("keeper response has no 'values' object")
	}
	return out.Values, out.State, out.Errors, out.Unresolved, nil
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
