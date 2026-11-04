package broker

import (
	"bytes"
	"log"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
)

// A refusal's record that cannot be written still leaves the refusal standing,
// and the loss reaches the journal under the id the caller was given.
func TestALostRefusalRecordIsLoggedUnderItsLogID(t *testing.T) {
	s := newServer(t, map[string]string{})
	// A regular file where the log's directory should be: no uid can create it.
	blocker := filepath.Join(t.TempDir(), "not-a-dir")
	if err := os.WriteFile(blocker, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	s.Audit = audit.NewLog(config.AuditConfig{LogPath: filepath.Join(blocker, "audit.jsonl")})

	var journal bytes.Buffer
	previous := log.Writer()
	log.SetOutput(&journal)
	t.Cleanup(func() { log.SetOutput(previous) })

	response := s.refuse(s.Store.Snapshot(), "bad_request", "no cwd", "LOGID-1", nil, nil, "")
	if code := errorCode(t, response); code != "bad_request" {
		t.Errorf("error code %q, want the refusal's own bad_request", code)
	}
	got := journal.String()
	if !strings.Contains(got, "LOGID-1 audit record not written: ") || !strings.Contains(got, blocker) {
		t.Errorf("journal = %q, want the log_id, the loss and the path", got)
	}
	if n := strings.Count(got, "\n"); n != 1 {
		t.Errorf("journal has %d lines, want one report of the loss: %q", n, got)
	}
}
