package secretstore

// The keeper socket's client. The store reaches values only by asking: nothing
// here has access to the key, the sops invocation, or the decrypted set.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// callTimeout bounds one round trip to the keeper, decryption included. Above
// the keeper's own decryptBudget, which is what bounds the reply: this is the
// backstop for a keeper that accepts a connection and then answers nothing, not
// a limit on how long decryption may legitimately take. Kept as a separate
// constant because this package shares no code with the one holding the key.
const callTimeout = 10 * time.Minute

// errReplyTooLarge is a value set larger than one reply may carry. Its own
// sentinel because it is permanent where every other failure to reach the
// keeper is transient: retrying re-decrypts the whole store and cannot
// succeed, so the store treats it as a load failure rather than an outage.
var errReplyTooLarge = errors.New("the keeper's reply is too large")

// maxReplyBytes bounds one keeper reply, which for get_values is every managed
// value plus the fingerprints, JSON-encoded. Generous rather than tuned: it is
// a guard against a reply that will not end, and a store anywhere near it is a
// store to split.
const maxReplyBytes = 1 << 24

// fileState is one managed file's fingerprint. Comparable, since the staleness
// check is set equality over these, and it carries no contents.
type fileState struct {
	Path  string `json:"path"`
	MTime int64  `json:"mtime_unix_nano"`
	Size  int64  `json:"size"`
}

// response is every field either op can return: they differ in which fields
// they fill, not in the envelope.
type response struct {
	Values map[string]string `json:"values"`
	State  []fileState       `json:"state"`
	Errors []string          `json:"errors"`
	// UnresolvedPatterns is the entries that named nothing, kept apart from
	// Errors: a secrets directory not written yet is what a first install looks
	// like, and a file that is there and will not open is a value the redactor is
	// missing.
	UnresolvedPatterns []string `json:"unresolved_patterns"`
	// ShadowedRefs is the refs more than one managed file defines with different
	// values, by ref and by which files. One value wins and the other is in no
	// redactor, so this is a repair list rather than a diagnostic.
	ShadowedRefs map[string]string `json:"shadowed_refs"`
	Error        *struct {
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

	if err := sockutil.Send(conn, map[string]any{
		"op": op, "version": version.Version}); err != nil {
		return nil, fmt.Errorf("keeper: %w", err)
	}
	if uc, ok := conn.(*net.UnixConn); ok {
		_ = uc.CloseWrite()
	}
	line, err := sockutil.ReadLine(conn, maxReplyBytes)
	if err != nil {
		if errors.Is(err, sockutil.ErrTooLarge) {
			// The reply carries every decrypted value, so this is a managed store
			// that outgrew the limit rather than anything wrong with the socket.
			// Named as such: reported as the keeper being unreachable it sent an
			// operator looking at a daemon that answered perfectly well.
			return nil, fmt.Errorf("%w: the reply is every managed value at once and "+
				"is larger than %d bytes, so this store is too big to serve. Split it, "+
				"or shorten what it holds", errReplyTooLarge, maxReplyBytes)
		}
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

// valueSet is one answer to get_values: what the keeper served, and what it could
// not. A struct rather than a row of returns, several of which are "what went
// wrong" in different shapes and were told apart only by position.
type valueSet struct {
	Values             map[string]string
	State              []fileState
	Errors             []string
	UnresolvedPatterns []string
	// ShadowedRefs is the refs more than one managed file defines with different
	// values. One value wins and the other reaches no redactor, which is the same
	// missing as a value too short to cover rather than a file that would not
	// open, so it is carried apart from Errors and does not stop the broker
	// serving.
	ShadowedRefs map[string]string
}

// fetchValues asks the keeper for the decrypted value set and the fingerprints
// of the files it decrypted. Every value, not a subset, and the state comes
// back with them so the two describe the same moment. A per-file failure is in
// Errors rather than an error, so one broken file does not blank the set.
func fetchValues(socketPath string) (valueSet, error) {
	out, err := call(socketPath, "get_values")
	if err != nil {
		return valueSet{}, err
	}
	if out.Values == nil {
		return valueSet{}, errors.New("keeper response has no 'values' object")
	}
	return valueSet{
		Values:             out.Values,
		State:              out.State,
		Errors:             out.Errors,
		UnresolvedPatterns: out.UnresolvedPatterns,
		ShadowedRefs:       out.ShadowedRefs,
	}, nil
}

// fetchState asks the keeper which managed files exist and when they changed:
// no key, no sops, no contents, so it is what the broker polls with. A file
// the keeper could not stat is in the errors slice and absent from the state,
// which reads as a change and reloads.
func fetchState(socketPath string) ([]fileState, []string, error) {
	out, err := call(socketPath, "get_state")
	if err != nil {
		return nil, nil, err
	}
	return out.State, out.Errors, nil
}
