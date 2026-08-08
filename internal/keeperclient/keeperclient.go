// Package keeperclient talks to the keeper socket.
//
// It is deliberately separate from the keeper itself.  The keeper links sops,
// which pulls in every key source sops supports (AWS KMS, GCP KMS, Azure Key
// Vault, Vault, PGP) and their transitive dependencies.  The broker needs none
// of that: it asks for values over a socket.  Keeping the client here is what
// stops that dependency tree being linked into the broker and the executor as
// well, and it is why only one of the four binaries carries it.
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
