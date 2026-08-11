package audit

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
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

	log.Write(map[string]any{"log_id": "before"}, Output{})
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	log.Write(map[string]any{"log_id": "after"}, Output{})

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
		log.Write(map[string]any{"log_id": "test"}, Output{Text: raw})
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

// Invariant 1: one record is one line, and no line exceeds max_record_bytes,
// counted in the bytes the line spends rather than the bytes a command wrote.
//
// The table is what a command can choose from: '<' and a C0 control each cost
// six as JSON, an invalid byte three.  A cap counted before encoding is a cap
// whose meaning the command picks, which is how 1.4MB of output became an 8MB
// line.
func TestNoRecordExceedsTheCapWhateverACommandPrints(t *testing.T) {
	const cap = 64 * 1024
	for _, tc := range []struct{ name, output string }{
		{"plain text", strings.Repeat("ok: [host.example.com]\n", 200_000)},
		{"angle brackets", strings.Repeat("<", 4_000_000)},
		{"ampersands", strings.Repeat("&", 4_000_000)},
		{"C0 controls", strings.Repeat("\x01", 4_000_000)},
		{"invalid bytes", strings.Repeat("\xff", 4_000_000)},
		{"line separators", strings.Repeat(" ", 1_000_000)},
		{"one enormous rune run", strings.Repeat("é", 2_000_000)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "audit.log")
			NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: cap}).
				Write(map[string]any{"log_id": "x", "op": "exec"}, Output{Text: tc.output})

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > cap {
				t.Errorf("the record is %d bytes for a cap of %d", len(data), cap)
			}
			if n := strings.Count(string(data), "\n"); n != 1 {
				t.Errorf("the record is %d lines, want 1", n)
			}
			var record map[string]any
			if err := json.Unmarshal(data, &record); err != nil {
				t.Fatalf("the record does not parse: %v", err)
			}
			if record["output_truncated"] != true {
				t.Error("output was dropped and the record does not say so")
			}
		})
	}
}

// The other fields are the caller's too.  argv is the one that matters: execve
// will take two megabytes of it, and nothing between the agent and this record
// shortens it.
func TestAnEnormousArgvStillFitsTheCap(t *testing.T) {
	const cap = 64 * 1024
	path := filepath.Join(t.TempDir(), "audit.log")
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: cap}).Write(map[string]any{
		"log_id": "x", "op": "exec",
		"cmd": []string{"bash", "-c", strings.Repeat("<", 2_000_000)},
		"cwd": strings.Repeat("d", 100_000),
	}, Output{})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > cap {
		t.Fatalf("the record is %d bytes for a cap of %d", len(data), cap)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("the record does not parse: %v", err)
	}
	if record["log_id"] != "x" {
		t.Errorf("the record lost its identity while being cut down: %v", record)
	}
}

// An excerpt is the head and the tail: what an operator wants from a long run is
// how it started and how it ended, and a prefix is the half that is never the
// answer.
func TestAnExcerptKeepsBothEnds(t *testing.T) {
	output := "FIRST-LINE\n" + strings.Repeat("filler\n", 200_000) + "LAST-LINE\n"
	text, dropped := Excerpt(output, 8*1024)
	if dropped == 0 {
		t.Fatal("nothing was dropped from a 1.4MB output")
	}
	if !strings.HasPrefix(text, "FIRST-LINE\n") {
		t.Error("the excerpt does not start where the run did")
	}
	if !strings.HasSuffix(text, "LAST-LINE\n") {
		t.Error("the excerpt does not end where the run did")
	}
	if !strings.Contains(text, "bytes of output dropped") {
		t.Error("the excerpt does not say that it is one")
	}
}

// Short output is recorded as it was written: an excerpt of something that fits
// is the thing itself.
func TestOutputThatFitsIsUntouched(t *testing.T) {
	output := "ok: [host.example.com]\nchanged=0\n"
	text, dropped := Excerpt(output, 8*1024)
	if text != output || dropped != 0 {
		t.Errorf("Excerpt altered output that fits: %q, dropped %d", text, dropped)
	}
}

// encodedLen has to agree with the encoder it is standing in for, or the cap is
// counted in the wrong unit and every guarantee resting on it is arithmetic
// about the wrong number.
func TestEncodedLenAgreesWithTheEncoder(t *testing.T) {
	for _, s := range []string{
		"plain", "<tag>", "a&b", "\x01\x02", "\xff\xfe", "tab\there", "nl\nhere",
		`quote"and\backslash`, "héllo wörld", "  ", "",
	} {
		line, err := json.Marshal(s)
		if err != nil {
			t.Fatal(err)
		}
		// The marshalled form carries the two quotes around it.
		if want, got := len(line)-2, encodedLen(s); got != want {
			t.Errorf("encodedLen(%q) = %d, encoder spends %d", s, got, want)
		}
	}
}

// Invariant 3: an id is distinct by construction.  Two random bytes collided 14
// times in 1,600 records on a live install, twice for the whole id, and a lookup
// shows the first match and says nothing about the second.
func TestLogIDsDoNotRepeat(t *testing.T) {
	const n = 200_000
	seen := make(map[string]struct{}, n)
	for range n {
		id := NewLogID()
		if _, dup := seen[id]; dup {
			t.Fatalf("log_id %s was issued twice in %d", id, n)
		}
		seen[id] = struct{}{}
	}
}

// Concurrently too: the counter is what orders them, and it is shared.
func TestLogIDsDoNotRepeatAcrossGoroutines(t *testing.T) {
	const workers, each = 8, 20_000
	ids := make(chan string, workers*each)
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for range each {
				ids <- NewLogID()
			}
		}()
	}
	wg.Wait()
	close(ids)
	seen := make(map[string]struct{}, workers*each)
	for id := range ids {
		if _, dup := seen[id]; dup {
			t.Fatalf("log_id %s was issued twice", id)
		}
		seen[id] = struct{}{}
	}
}

// Invariant 2: an append is exclusive, so concurrent writers cannot interleave
// and every line parses.  Two Logs over one path is what `faramir edit` beside a
// running broker looks like.
func TestConcurrentWritersLeaveEveryLineParseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	cfg := config.AuditConfig{LogPath: path, MaxRecordBytes: 64 * 1024}

	const writers, each = 6, 40
	var wg sync.WaitGroup
	for w := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			log := NewLog(cfg) // its own Log, as another process would have
			for i := range each {
				log.Write(map[string]any{
					"log_id": NewLogID(), "op": "exec",
					"cmd": []string{"echo", fmt.Sprintf("w%d-i%d", w, i)},
				}, Output{Text: strings.Repeat("<", 20_000)})
			}
		}()
	}
	wg.Wait()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimRight(string(data), "\n"), "\n")
	if len(lines) != writers*each {
		t.Fatalf("got %d lines, want %d", len(lines), writers*each)
	}
	for i, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("line %d does not parse, so two appends interleaved: %v", i+1, err)
		}
	}
}

// The collector bounds what a run holds in memory as it streams, so a command
// that prints for an hour costs what one record costs.  Both ends survive it.
func TestCollectorKeepsBothEndsOfALongRun(t *testing.T) {
	c := NewCollector(8 * 1024)
	c.Add("FIRST-CHUNK\n")
	for range 5_000 {
		c.Add(strings.Repeat("filler ", 100) + "\n")
	}
	c.Add("LAST-CHUNK\n")

	out := c.Output()
	if out.Dropped == 0 {
		t.Fatal("nothing was dropped from a 3.5MB run")
	}
	if encodedLen(out.Text) > 8*1024 {
		t.Errorf("the collector kept %d encoded bytes for a budget of 8192",
			encodedLen(out.Text))
	}
	if !strings.HasPrefix(out.Text, "FIRST-CHUNK\n") {
		t.Error("the head of the run was not kept")
	}
	if !strings.HasSuffix(out.Text, "LAST-CHUNK\n") {
		t.Error("the tail of the run was not kept")
	}
}

// One chunk larger than the whole budget is the case a ring of chunks gets
// wrong: there is no earlier chunk to drop, so the chunk itself has to give.
func TestCollectorBoundsASingleEnormousChunk(t *testing.T) {
	c := NewCollector(8 * 1024)
	c.Add(strings.Repeat("<", 2_000_000) + "END")
	out := c.Output()
	if encodedLen(out.Text) > 8*1024 {
		t.Errorf("the collector kept %d encoded bytes for a budget of 8192",
			encodedLen(out.Text))
	}
	if !strings.HasSuffix(out.Text, "END") {
		t.Error("the end of the chunk was not kept")
	}
}

// Unwritable is what makes the refusal possible: it is asked before a command
// runs, so a filesystem with no room is a refusal the caller is told about
// rather than a command that ran with nothing to show for it.
func TestUnwritableNamesAnUnopenableLog(t *testing.T) {
	// A path under a file rather than a directory: ENOTDIR on every open.
	dir := t.TempDir()
	blocker := filepath.Join(dir, "not-a-directory")
	if err := os.WriteFile(blocker, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(blocker, "audit.log"), MaxRecordBytes: 64 * 1024,
	})
	if reason := log.Unwritable(); reason == "" {
		t.Error("a log that cannot be opened reports as writable")
	}
}

func TestUnwritableIsSilentOnAWorkingLog(t *testing.T) {
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(t.TempDir(), "audit.log"), MaxRecordBytes: 64 * 1024,
	})
	if reason := log.Unwritable(); reason != "" {
		t.Errorf("a writable log reports %q", reason)
	}
}
