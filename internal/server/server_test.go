package server

import (
	"encoding/json"
	"net"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
)

// fakeKeeper serves a fixed value set, so the agent-facing responses can be
// exercised without sops, an age key, or a real keeper.
func fakeKeeper(t *testing.T, values map[string]string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "keeper.sock")
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			_ = sockutil.Send(conn, map[string]any{"values": values, "errors": []string{}})
			_ = conn.Close()
		}
	}()
	t.Cleanup(func() { ln.Close() })
	return path
}

func newServer(t *testing.T, values map[string]string) *Server {
	t.Helper()
	dir := t.TempDir()
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath: filepath.Join(dir, "broker.sock"), SocketMode: 0o660,
			MaxConcurrency: 2, MaxRequestBytes: 262144,
		},
		Keeper: config.KeeperConfig{SocketPath: fakeKeeper(t, values)},
		Exec: config.ExecConfig{
			DefaultCwd: dir, DefaultTimeoutSec: 30, MaxTimeoutSec: 60,
			BaseEnv: map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Secrets: config.SecretsConfig{
			RefreshIntervalSec: 0, MinLength: 8, MinUniqueChars: 4,
			MinEntropyBitsPerChar: 1.5,
		},
		Audit: config.AuditConfig{RawLog: filepath.Join(dir, "raw.log"), MaxRecordBytes: 1 << 20},
	}
	s := New(cfg)
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

// -- the --check path -------------------------------------------------------

func TestCheckPrintsOneJSONObject(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	body, code := s.CheckOutput()
	if code != 0 {
		t.Errorf("exit = %d, want 0", code)
	}
	var out map[string]any
	if err := json.Unmarshal(body, &out); err != nil {
		t.Fatalf("not one JSON object: %v\n%s", err, body)
	}
	if _, ok := out["secrets"]; !ok {
		t.Errorf("no secrets key: %s", body)
	}
	// The allowlist is gone; --check must not still claim to report rules.
	if _, ok := out["allow_rules"]; ok {
		t.Errorf("--check still reports allow_rules: %s", body)
	}
}

func TestCheckNamesTheRefusedRefsAndTheReason(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	body, _ := s.CheckOutput()
	if !strings.Contains(string(body), "tiny") {
		t.Errorf("the refused ref was not named: %s", body)
	}
	if !strings.Contains(string(body), "shorter than") {
		t.Errorf("the reason was not given: %s", body)
	}
}

// --check is the install gate: the config parses, but a command injecting that
// ref will fail at runtime, so it must not report success.
func TestCheckExitsNonZeroWhenARefWasRefused(t *testing.T) {
	s := newServer(t, map[string]string{"tiny": "abc"})
	if _, code := s.CheckOutput(); code == 0 {
		t.Error("--check succeeded with a refused ref")
	}
}

// -- agent-facing responses -------------------------------------------------

func TestListSecretsOmitsARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opListSecrets())
	if !strings.Contains(body, "secret://good") {
		t.Errorf("a loaded ref is missing: %q", body)
	}
	if strings.Contains(body, "tiny") {
		t.Errorf("a refused ref was listed: %q", body)
	}
}

func TestListSecretsEndsEveryLine(t *testing.T) {
	s := newServer(t, map[string]string{
		"a": "hunter2-correct-horse", "b": "another-good-value",
	})
	body := output(t, s.opListSecrets())
	if body == "" {
		t.Fatal("empty output")
	}
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("the last line is unterminated: %q", body)
	}
	for _, line := range strings.Split(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "secret://") {
			t.Errorf("unexpected line: %q", line)
		}
	}
}

func TestListSecretsIsEmptyWhenNothingLoaded(t *testing.T) {
	s := newServer(t, map[string]string{})
	if body := output(t, s.opListSecrets()); body != "" {
		t.Errorf("output = %q, want empty", body)
	}
}

// A value that is never tokenized is one worth targeting, so status must not
// name it, and must not carry the operator-only refusal list.
func TestStatusDoesNotNameARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opStatus())
	if strings.Contains(body, "tiny") {
		t.Errorf("status named a refused ref: %q", body)
	}
	if strings.Contains(body, "not_redactable") {
		t.Errorf("status carried the refusal list: %q", body)
	}
	if !strings.Contains(body, "ref_count") {
		t.Errorf("status is missing ref_count: %q", body)
	}
	// Both removed upstream; status must not still advertise them.
	for _, gone := range []string{"allow_rules", "sync_enabled"} {
		if strings.Contains(body, gone) {
			t.Errorf("status still reports %s: %q", gone, body)
		}
	}
}

func TestStatusNeverCarriesAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	if body := output(t, s.opStatus()); strings.Contains(body, secret) {
		t.Errorf("status leaked a value: %q", body)
	}
}

// An unexpected error string can have interpolated a secret, so it goes
// through the redactor like every other agent-visible string.
func TestSafeDetailRedactsAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	got := s.safeDetail("exec failed: could not connect with " + secret)
	if strings.Contains(got, secret) {
		t.Errorf("an error message leaked a value: %q", got)
	}
	if !strings.Contains(got, "«SECRET:a/b»") {
		t.Errorf("no token in %q", got)
	}
}
