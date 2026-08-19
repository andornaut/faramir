// Package keeperclient talks to the keeper socket. Separate from the keeper
// itself so the broker reaches values only by asking, in code with no access to
// the key, the sops invocation, or the decrypted set.
package keeperclient

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
)

// callTimeout bounds one round trip to the keeper, decryption included. Above
// the keeper's own decryptBudget, which is what bounds the reply: this is the
// backstop for a keeper that accepts a connection and then answers nothing, not
// a limit on how long decryption may legitimately take. Kept as a separate
// constant because this package shares no code with the one holding the key.
const callTimeout = 10 * time.Minute

// FileState is one managed file's fingerprint. Comparable, since the staleness
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
	// UnresolvedPatterns is the entries that named nothing, kept apart from
	// Errors: a secrets directory not written yet is what a first install looks
	// like, and a file that is there and will not open is a value the redactor is
	// missing.
	UnresolvedPatterns []string `json:"unresolved_patterns"`
	Error              *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

// call sends one request and decodes the reply.
func call(socketPath, op string) (*response, error) {
	conn, err := (&net.Dialer{}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("keeper socket %s: %w", socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	// The caller is the broker serving a request whose own read deadline has
	// already been cleared, so without this a keeper that accepts and never
	// answers leaves `faramir run` hanging with nothing to report. Generous:
	// get_values execs sops once per managed file.
	_ = conn.SetDeadline(time.Now().Add(callTimeout))

	if err := sockutil.Send(conn, map[string]any{"op": op}); err != nil {
		return nil, fmt.Errorf("keeper: %w", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, 1<<24)
	if err != nil {
		return nil, fmt.Errorf("keeper: %w", err)
	}
	if len(line) == 0 {
		return nil, errors.New("keeper closed the connection without responding")
	}

	var out response
	if err := json.Unmarshal(line, &out); err != nil {
		return nil, fmt.Errorf("malformed response from keeper: %w", err)
	}
	if out.Error != nil {
		return nil, fmt.Errorf("keeper: %s: %s", out.Error.Code, out.Error.Message)
	}
	return &out, nil
}

// FetchValues asks the keeper for the decrypted value set and the fingerprints
// of the files it decrypted. Every value, not a subset, and the state comes
// back with them so the two describe the same moment. A per-file failure is in
// the errors slice rather than an error, so one broken file does not blank the
// set.
func FetchValues(socketPath string) (map[string]string, []FileState, []string, []string, error) {
	out, err := call(socketPath, "get_values")
	if err != nil {
		return nil, nil, nil, nil, err
	}
	if out.Values == nil {
		return nil, nil, nil, nil, errors.New("keeper response has no 'values' object")
	}
	return out.Values, out.State, out.Errors, out.UnresolvedPatterns, nil
}

// FetchState asks the keeper which managed files exist and when they changed:
// no key, no sops, no contents, so it is what the broker polls with. A file
// the keeper could not stat is in the errors slice and absent from the state,
// which reads as a change and reloads.
func FetchState(socketPath string) ([]FileState, []string, error) {
	out, err := call(socketPath, "get_state")
	if err != nil {
		return nil, nil, err
	}
	return out.State, out.Errors, nil
}
