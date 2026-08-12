// Package keepertest serves the keeper's protocol from a value set a test
// chooses, so the broker and its store run without sops, an age key or a real
// keeper.  Imported only from _test.go files.
//
// One stand-in rather than a copy per package: the staleness check is set
// equality over keeper.FileState, so the fingerprints come from the real
// keeper.StatAll.
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
	// Listener is exposed so a test can close it mid-run.
	Listener net.Listener

	mu     sync.Mutex
	values map[string]string
	errors []string
	files  []string
}

// New serves values on a socket of its own.  files is the managed inventory
// this keeper reports on, given here because the broker stats no managed file
// itself.
func New(t *testing.T, values map[string]string, files ...string) *Keeper {
	t.Helper()
	return Serve(t, filepath.Join(t.TempDir(), "keeper.sock"), values, files...)
}

// Serve binds a named socket, so a test can start one after the broker's store
// has already tried and failed to reach it.
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
		// Read before answering, as the real keeper does: closing mid-write
		// gives the client EPIPE.
		line, _ := sockutil.ReadLine(conn, 1<<16)
		var request struct {
			Op string `json:"op"`
		}
		_ = json.Unmarshal(line, &request)

		k.mu.Lock()
		state, errors, unresolved := keeper.StatAll(config.SecretsConfig{Patterns: k.files})
		payload := map[string]any{"state": state, "errors": errors, "unresolved_patterns": unresolved}
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
// edit to a managed file is simulated.
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

// SetFiles replaces the managed inventory, for a caller that configures the
// secrets after the keeper is up.  Both get the same list.
func (k *Keeper) SetFiles(files []string) {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.files = files
}
