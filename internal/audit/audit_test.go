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
	// "é" is two bytes, so a limit of 3 lands inside the second.
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

// logrotate renames the log away underneath a running broker, so without a fresh
// open per write every record until the next restart lands in the renamed
// file.
func TestARecordAfterARotationOpensANewLog(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: 1 << 16})

	log.Write(map[string]any{"log_id": "before"}, "")
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	log.Write(map[string]any{"log_id": "after"}, "")

	current, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("nothing was written after the rotation: %v", err)
	}
	if !strings.Contains(string(current), `"after"`) {
		t.Errorf("the record after the rotation is not in the new log: %s", current)
	}
	if strings.Contains(string(current), `"before"`) {
		t.Errorf("the new log holds a record from before the rotation: %s", current)
	}
	rotated, err := os.ReadFile(path + ".1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(rotated), `"before"`) {
		t.Errorf("the rotated log lost the record that was already in it: %s", rotated)
	}

	// The new file has to be created with the mode: 0644 would hand the command
	// output it carries to every account on the host.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("the log created after the rotation is %o, want 600", got)
	}
}

// A child printing binary puts an invalid byte mid-stream.  Only a partial rune
// at the very end may be trimmed.
func TestCutAtRuneKeepsOutputAfterAnInteriorInvalidByte(t *testing.T) {
	raw := "aaaa\xffbbbb"
	got := cutAtRune(raw, 9)
	if got != raw[:9] {
		t.Errorf("got %q (%d bytes), want the first 9 bytes intact", got, len(got))
	}
}

// The same case through the log: a record cut back to the first bad byte audits
// nothing.
func TestARecordWithBinaryOutputIsNotGutted(t *testing.T) {
	dir := t.TempDir()
	limit := 1 << 16
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(dir, "audit.log"), MaxRecordBytes: limit,
	})

	// One bad byte halfway through, then a marker before the cut.
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

// A write cut short leaves a line with no newline on the end, and the next
// record appends straight onto it: one failure takes two records, the second of
// them one that was written successfully, and `faramir logs` skips both without
// distinguishing either from the torn final line a concurrent read sees.
//
// The failure itself needs a full filesystem, which a test cannot ask for, so
// what is asserted here is the decision that follows one.
func TestLeftOpenRecognisesAWriteCutShort(t *testing.T) {
	line := []byte(`{"log_id":"a"}` + "\n")
	for _, tc := range []struct {
		name    string
		written int
		want    bool
	}{
		{"nothing landed, so there is no line to close", 0, false},
		{"cut in the middle", 5, true},
		{"cut one byte short of the newline", len(line) - 1, true},
		{"the whole line landed", len(line), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := leftOpen(line, tc.written); got != tc.want {
				t.Errorf("leftOpen(%d of %d) = %v, want %v", tc.written, len(line), got, tc.want)
			}
		})
	}
}
