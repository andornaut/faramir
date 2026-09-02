package broker

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// managedFile is a file for the managed store to name, so the store reports one
// as present. Contents are the keeper double's business, not this file's.
func managedFile(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "managed.sops.yml")
	if err := os.WriteFile(path, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// secretFiles is set here because the store copies the secrets config at
// construction, so a later assignment to s.Config.Secret reads nothing.
// newServer is a healthy install: one managed file, present and read, which is
// what the exec and redact gate asks for. A test that wants the store
// unconfigured calls newUnconfiguredServer.
func newServer(t *testing.T, values map[string]string, secretFiles ...string) *Server {
	t.Helper()
	if len(secretFiles) == 0 {
		secretFiles = []string{managedFile(t)}
	}
	return serverWith(t, keepertest.New(t, values, secretFiles...), secretFiles...)
}

// newUnconfiguredServer names no managed store, which is a broker holding an
// empty value set: it serves, there being no managed value for output to carry.
func newUnconfiguredServer(t *testing.T, values map[string]string) *Server {
	t.Helper()
	return serverWith(t, keepertest.New(t, values))
}

// newUnreadableServer is the state that does refuse: a managed file that was
// found and did not load, where the broker knows values exist and cannot cover
// them.
func newUnreadableServer(t *testing.T) *Server {
	t.Helper()
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, file)
	k.SetErrors([]string{file + ": could not decrypt"})
	s := serverWith(t, k, file)
	s.Store.Reload()
	if s.Store.Unreadable() == "" {
		t.Fatal("the fixture does not refuse: a file that did not load should")
	}
	return s
}

// serverWith is newServer against a keeper the caller already has, for a test
// that has to reach into it.
func serverWith(t *testing.T, k *keepertest.Keeper, secretFiles ...string) *Server {
	t.Helper()
	// No staleness gate: these tests drive the store by hand, and the interval
	// is a constant in the binary rather than a key this config could set.
	wasInterval := config.MinRefreshSec
	config.MinRefreshSec = 0
	t.Cleanup(func() { config.MinRefreshSec = wasInterval })
	dir := t.TempDir()
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath: filepath.Join(dir, "broker.sock")},
		Keeper: config.KeeperConfig{SocketPath: k.Path},
		Command: config.CommandConfig{
			TimeoutSec: 30, MaxTimeoutSec: 60, Concurrency: 10,
			Env: map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Secret: config.SecretConfig{Patterns: secretFiles, MinLength: 8},
		Audit:  config.AuditConfig{LogPath: filepath.Join(dir, "audit.log")},
	}
	s := New(nil, cfg)
	s.Store.Reload()
	return s
}

func output(t *testing.T, r protocol.Response) string {
	t.Helper()
	out, ok := r["output"].(string)
	if !ok {
		t.Fatalf("response has no string output: %v", r)
	}
	return out
}

// -- the request limit ------------------------------------------------------

// Produced before a request is parsed, so it has its own code rather than being
// a bad_request: an oversized request is a client that needs to send less, not
// one that sent nonsense. `faramir redact` withholds the text either way, as it
// does for every other error -- text that reached no redactor is text nobody
// checked -- and the code is what tells the two apart in the audit and to
// whoever is reading the failure.
func TestARequestOverTheLimitIsRefusedAsTooLarge(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	// Restored, this being a package variable rather than a field on the server:
	// left at 64 it is every later test's limit too, and the ones that send a
	// stream are refused as too_large.
	was := config.MaxRequestBytes
	config.MaxRequestBytes = 64
	t.Cleanup(func() { config.MaxRequestBytes = was })
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })

	conn, err := (&net.Dialer{}).DialContext(t.Context(), "unix", s.Config.Server.SocketPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	body := `{"op":"redact","text":"` + strings.Repeat("x", 200) + `"}` + "\n"
	if _, err := conn.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}

	line, err := sockutil.ReadLine(conn, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	var out struct {
		Error *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	if out.Error == nil {
		t.Fatalf("an oversized request was accepted: %s", line)
	}
	if out.Error.Code != "too_large" {
		t.Errorf("code = %q, want too_large", out.Error.Code)
	}
	// The limit itself: the caller's only remedy is to send less.
	if !strings.Contains(out.Error.Message, "64") {
		t.Errorf("the message does not say what the limit is: %q", out.Error.Message)
	}
}
