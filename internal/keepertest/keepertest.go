// Package keepertest serves the keeper's protocol from a value set a test
// chooses, so the broker and its store can be exercised without sops, an age
// key, or a real keeper.
//
// It is imported only from _test.go files.  One stand-in rather than a copy in
// each package that needs one: the store's staleness check is set equality over
// keeper.FileState, so a stand-in that built those differently would pass while
// production did not, and two copies drift into exactly that.  The fingerprints
// come from the real keeper.StatAll for the same reason.
package keepertest

import (
	"encoding/json"
	"net"
	"path/filepath"
	"sync"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/sockutil"
)

// Keeper is one stand-in, already listening.
type Keeper struct {
	// Path is the socket to point a store or a broker at.
	Path string
	// Listener is exposed so a test can close it and leave a store with a keeper
	// it can no longer reach.
	Listener net.Listener

	mu     sync.Mutex
	values map[string]string
	errors []string
	files  []string
}

// New serves values on a socket of its own.
//
// files is the managed inventory this keeper reports on.  It is given here
// rather than read from the store's config because the store no longer stats
// those files: an absent or unreadable one is the keeper's report, and that
// report is what the broker's load gate fails on.
func New(t *testing.T, values map[string]string, files ...string) *Keeper {
	t.Helper()
	return Serve(t, filepath.Join(t.TempDir(), "keeper.sock"), values, files...)
}

// Serve binds a named socket, so a test can start one after the store has
// already tried and failed to reach it.
func Serve(t *testing.T, path string, values map[string]string, files ...string) *Keeper {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	k := &Keeper{Path: path, Listener: ln, values: values, files: files}
	go k.accept()
	t.Cleanup(func() { _ = ln.Close() })
	return k
}

func (k *Keeper) accept() {
	for {
		conn, err := k.Listener.Accept()
		if err != nil {
			return
		}
		// Read the request before answering, as the real keeper does.  Closing
		// while the client is still writing gives it EPIPE, which surfaces as an
		// intermittently empty value set.
		line, _ := sockutil.ReadLine(conn, 1<<16)
		var request struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(line, &request)

		k.mu.Lock()
		state, errors := keeper.StatAll(config.SecretsConfig{Files: k.files})
		payload := map[string]any{"state": state, "errors": errors}
		if request.Op != "get_state" {
			payload["values"] = k.values
			payload["errors"] = append(errors, k.errors...)
		}
		k.mu.Unlock()
		_ = sockutil.Send(conn, payload)
		_ = conn.Close()
	}
}

// SetValues replaces what the next get_values answers with, which is how an
// edit to the store is simulated.
func (k *Keeper) SetValues(values map[string]string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.values = values
}

// SetErrors adds per-file failures to the next get_values, the way a keeper
// that could not decrypt one reports it.
func (k *Keeper) SetErrors(errors []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.errors = errors
}

// SetFiles replaces the managed inventory.  For a caller that configures the
// store after the keeper is already up: the two are given the same list,
// because the two disagreeing is not a case a real install can produce.
func (k *Keeper) SetFiles(files []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.files = files
}
