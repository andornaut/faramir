package main

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
)

// A record the log will not take is reported on the real stderr, once, as one
// line naming the command and the path.
func TestALostAuditRecordIsReportedOnStderr(t *testing.T) {
	// A regular file where the log's directory should be: no uid can create it.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	sink := audit.NewLog(config.AuditConfig{LogPath: filepath.Join(blocker, "audit.jsonl")})

	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = r.Close() }()
	previous := os.Stderr
	os.Stderr = w
	writeAudit("vault add", sink, map[string]any{"op": opAdd, "log_id": audit.NewLogID()})
	os.Stderr = previous
	_ = w.Close()
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}

	got := string(out)
	if !strings.HasPrefix(got, "faramir vault add: audit record not written: ") || !strings.Contains(got, blocker) {
		t.Errorf("stderr = %q, want the command, the loss and the path", got)
	}
	if n := strings.Count(got, "\n"); n != 1 {
		t.Errorf("stderr has %d lines, want one: %q", n, got)
	}
}
