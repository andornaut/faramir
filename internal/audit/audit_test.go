package audit

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/config"
)

func TestCutAtRuneKeepsWholeRunes(t *testing.T) {
	// "é" is two bytes, so a limit of 3 lands inside the second one.
	if got := cutAtRune("aé", 2); got != "a" {
		t.Errorf("got %q, want %q", got, "a")
	}
	if got := cutAtRune("aéb", 3); got != "aé" {
		t.Errorf("got %q, want %q", got, "aé")
	}
	if got := cutAtRune("abc", 10); got != "abc" {
		t.Errorf("a string under the limit was altered: %q", got)
	}
}

// A child printing binary puts an invalid byte in the middle of the stream.
// Backing off to the first valid prefix would drop everything after it, and
// take O(n^2) to do so; only a partial rune at the very end may be trimmed.
func TestCutAtRuneKeepsOutputAfterAnInteriorInvalidByte(t *testing.T) {
	raw := "aaaa\xffbbbb"
	got := cutAtRune(raw, 9)
	if got != raw[:9] {
		t.Errorf("got %q (%d bytes), want the first 9 bytes intact", got, len(got))
	}
}

// The same case through the log itself: the record has to hold what the child
// printed: a record cut back to the first bad byte audits nothing.
func TestARecordWithBinaryOutputIsNotGutted(t *testing.T) {
	dir := t.TempDir()
	limit := 1 << 16
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(dir, "audit.log"), MaxRecordBytes: limit,
	})

	// One bad byte halfway through, then a marker just before the cut.
	raw := strings.Repeat("a", limit/2) + "\xff" +
		strings.Repeat("b", limit/2-16) + "TAIL-MARKER" + strings.Repeat("c", 1000)

	done := make(chan struct{})
	go func() {
		log.Write(map[string]any{"log_id": "test"}, raw)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("writing one record took over 10s; the truncation is superlinear")
	}

	data, err := os.ReadFile(filepath.Join(dir, "audit.log"))
	if err != nil {
		t.Fatal(err)
	}
	var record struct {
		Output    string `json:"output"`
		Truncated bool   `json:"output_truncated"`
	}
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if !record.Truncated {
		t.Error("an over-length record was not flagged as truncated")
	}
	if !strings.Contains(record.Output, "TAIL-MARKER") {
		t.Errorf("the record was cut back to the invalid byte: %d bytes kept, want ~%d",
			len(record.Output), limit)
	}
}
