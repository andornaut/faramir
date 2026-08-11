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
	"github.com/andornaut/faramir/internal/redact"
)

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

// A child printing binary puts an invalid byte mid-stream, and a record cut back
// to the first bad byte audits nothing.
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

// A record that does not fit is reduced, not discarded.  The ceiling reduce
// applies is counted in encoded bytes for the same reason the cap is: two
// hundred arguments of a thousand '<' each are 200KB raw, under any per-string
// limit worth having, and 1.2MB once encoded -- so a clamp counted in raw bytes
// changed nothing, the record stayed over the cap, and what landed was the
// identity stub: no cmd, no cwd, no exit code, no output.
func TestALargeArgvKeepsTheRestOfTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	args := []string{"bash", "-c"}
	for range 200 {
		args = append(args, strings.Repeat("<", 1000))
	}
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: 262144}).Write(map[string]any{
		"log_id": "x", "op": "exec", "cmd": args, "cwd": "/srv/work",
		"exit_code": 0.0,
	}, Output{Text: "the output of the run\n"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 262144 {
		t.Fatalf("the record is %d bytes for a cap of %d", len(data), 262144)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"log_id", "op", "cmd", "cwd", "exit_code", "output"} {
		if _, ok := record[key]; !ok {
			t.Errorf("the record lost %q while being cut down to fit", key)
		}
	}
	if record["record_reduced"] != true {
		t.Error("a reduced record does not say that it was reduced")
	}
	if got, _ := record["output"].(string); got != "the output of the run\n" {
		t.Errorf("output = %q, want it untouched: argv is what was too large", got)
	}
}

// The same in the other shape: many entries rather than long ones.  An env_refs
// map naming one value under thousands of names is over the cap however short
// each entry is, so a ceiling on strings alone leaves it unreachable.
func TestManyEntriesAreCutDownToo(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	refs := map[string]string{}
	for i := range 20_000 {
		refs[fmt.Sprintf("VAR_%05d", i)] = "home/router/admin"
	}
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: 65536}).Write(map[string]any{
		"log_id": "x", "op": "exec", "cmd": []string{"printenv"}, "env_refs": refs,
	}, Output{})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > 65536 {
		t.Fatalf("the record is %d bytes for a cap of %d", len(data), 65536)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	kept, _ := record["env_refs"].(map[string]any)
	if len(kept) == 0 {
		t.Fatal("every ref was dropped")
	}
	// Sorted, so which ones survive is the same on every run rather than whatever
	// the map happened to iterate to first.
	if _, ok := kept["VAR_00000"]; !ok {
		t.Errorf("kept %d refs and not the first in order: %v", len(kept), kept)
	}
}

// Output cut by reduce has to say so as well.  A record whose output was
// shortened and does not carry the flag reads as a complete one.
func TestOutputCutByReductionIsFlagged(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	// A cap at the floor, so even the reduced record is tight and the output field
	// is one of the things that has to give.
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: config.MinRecordBytes}).
		Write(map[string]any{
			"log_id": "x", "op": "exec",
			"cmd": []string{"bash", "-c", strings.Repeat("<", 200_000)},
		}, Output{Text: strings.Repeat("z", 3000)})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	got, _ := record["output"].(string)
	if len(got) >= 3000 {
		t.Skip("the output was not cut, so there is nothing to flag")
	}
	if record["output_truncated"] != true {
		t.Errorf("output was cut to %d bytes and the record does not say so: %v", len(got), record)
	}
}

// A run's output is recorded in the order it was written.  The head takes what
// fits until a chunk does not, and then it is shut: without that a chunk too
// large for the room left goes to the tail and a smaller one after it lands in
// the head, ahead of it, so the record shows the run out of order.
func TestTheCollectorDoesNotReorderOutput(t *testing.T) {
	c := NewCollector(2048)
	// The last two bytes of the head's budget: '<' costs six and will not fit,
	// "BB" costs two and would.
	c.Add(strings.Repeat("a", c.half()-2))
	c.Add("<")
	c.Add("BB")
	if got := c.Output().Text; !strings.HasSuffix(got, "<BB") {
		t.Errorf("output ends %q, want the chunks in the order they arrived", got[max(len(got)-8, 0):])
	}
}

// Unwritable is asked before every command, so it has to be about now.  Latching
// the answer made it a report on the host as it was at startup: a log made
// unwritable afterwards -- a read-only remount, an immutable bit, an owner
// changed by a hand-edited logrotate rule -- still answered yes, and every
// command ran with its record going nowhere, which is the state the check exists
// to rule out.
//
// Posed as ENOTDIR rather than as a mode, because the account that asks this in
// production is a daemon and the account that runs the tests is often root, and
// root opens a file whatever its mode says.
func TestUnwritableNoticesALogThatBreaksAfterTheFirstWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logdir")
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(dir, "audit.log"), MaxRecordBytes: 64 * 1024,
	})

	log.Write(map[string]any{"log_id": "first", "op": "exec"}, Output{})
	if reason := log.Unwritable(); reason != "" {
		t.Fatalf("a working log reports %q", reason)
	}

	// The directory the log lives in becomes a file, so every open under it fails
	// for everybody.
	if err := os.RemoveAll(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dir, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	if reason := log.Unwritable(); reason == "" {
		t.Error("a log that can no longer be opened for append reports as writable")
	}
}

// A long argv and a long run in the same command: the output is sized against
// what the rest of the record costs, so this is an ordinary record rather than
// a reduced one.  With the reserve fixed in advance the two added up past the
// cap and every such command was recorded with its fields cut.
func TestALongArgvAndALongRunFitWithoutReducing(t *testing.T) {
	const cap = 1 << 20
	path := filepath.Join(t.TempDir(), "audit.log")
	log := NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: cap})

	// argv at what [server] max_request_bytes would let through, and output at
	// what Collector streams against, which is the pair that has to coexist.
	args := []string{"ansible-playbook", "--extra-vars", strings.Repeat("x", 200_000)}
	collector := NewCollector(log.OutputBudget())
	collector.Add(strings.Repeat("ok: [host.example.com]\n", 60_000))

	log.Write(map[string]any{
		"log_id": "x", "op": "exec", "cmd": args, "cwd": "/srv/ansible",
		"exit_code": 0.0,
	}, collector.Output())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > cap {
		t.Fatalf("the record is %d bytes for a cap of %d", len(data), cap)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if record["record_reduced"] == true {
		t.Error("an ordinary command was recorded as a reduced record")
	}
	if got, _ := record["cmd"].([]any); len(got) != 3 {
		t.Errorf("argv was cut to %d arguments", len(got))
	}
	if got, _ := record["cmd"].([]any); len(got) == 3 {
		if arg, _ := got[2].(string); len(arg) != 200_000 {
			t.Errorf("the long argument was cut to %d bytes", len(arg))
		}
	}
}

// A record that has to be reduced keeps every field it was given.  The item
// ceiling is for collections a caller filled; applied to the payload itself it
// is a ceiling on the record's own fields, and it deleted them in reverse key
// order until few enough were left -- `redactions` first, which is what says
// which credentials the command used, leaving something that read as an
// ordinary complete record.
func TestReducingARecordKeepsEveryFieldOfIt(t *testing.T) {
	counts := make([]redact.Count, 0, 20_000)
	for i := range 20_000 {
		counts = append(counts, redact.Count{
			Token: fmt.Sprintf("«SECRET:team/service-%05d/password»", i), Count: 1,
		})
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: 1 << 20}).Write(map[string]any{
		"log_id": "x", "op": "exec", "cmd": []string{"ansible-playbook", "site.yml"},
		"cwd": "/srv/ansible", "exit_code": 0.0, "redactions": counts,
		"peer": map[string]any{"uid": 1001.0, "pid": 42.0},
	}, Output{Text: "the output an operator came to read\n"})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{
		"log_id", "op", "cmd", "cwd", "exit_code", "peer", "output", "redactions",
	} {
		if _, ok := record[key]; !ok {
			t.Errorf("the record lost %q while being reduced", key)
		}
	}
	// The list itself is what gives, and it says how much of it did.
	kept, _ := record["redactions"].([]any)
	if len(kept) == 0 || len(kept) >= 20_000 {
		t.Fatalf("redactions has %d entries, want it bounded and not empty", len(kept))
	}
	if last, _ := kept[len(kept)-1].(string); !strings.Contains(last, "more, cut to fit") {
		t.Errorf("a bounded list does not say what it left out: %v", kept[len(kept)-1])
	}
}

// The identity stub is the backstop for a record that cannot be made to fit.
// With every caller-chosen field bounded -- strings by encoded length, lists and
// maps by entry count, whatever their element type -- there is no record a
// caller can compose that reaches it, and this is the assertion that says so:
// the smallest cap the config allows, against every field as large as anything
// upstream could make it.
func TestNothingACallerSendsReachesTheStub(t *testing.T) {
	counts := make([]redact.Count, 0, 50_000)
	for i := range 50_000 {
		counts = append(counts, redact.Count{
			Token: fmt.Sprintf("«SECRET:%s-%05d»", strings.Repeat("deep/path/", 20), i), Count: i,
		})
	}
	refs := map[string]string{}
	for i := range 20_000 {
		refs[fmt.Sprintf("VAR_%05d_%s", i, strings.Repeat("N", 200))] = strings.Repeat("r", 500)
	}
	var args []string
	for range 5_000 {
		args = append(args, strings.Repeat("<", 2_000))
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: config.MinRecordBytes}).
		Write(map[string]any{
			"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "exec",
			"cmd": args, "cwd": strings.Repeat("<", 100_000), "env_refs": refs,
			"redactions": counts, "exit_code": 0.0,
			"peer":  map[string]any{"uid": 1001.0, "pid": 42.0, "gid": 1002.0},
			"error": strings.Repeat("&", 100_000),
		}, Output{Text: strings.Repeat("\x01", 500_000)})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > config.MinRecordBytes {
		t.Fatalf("the record is %d bytes for a cap of %d", len(data), config.MinRecordBytes)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"log_id", "op", "cmd", "cwd", "env_refs", "redactions", "peer", "error"} {
		if _, ok := record[key]; !ok {
			t.Errorf("the stub was reached: %q is gone. Record: %s", key, data)
		}
	}
}

// The terminal reduction is reached when a record's field set is what is too
// large, which is the code's to decide and not a caller's.  Kept and tested
// rather than deleted as unreachable: it is what makes encode total, and the day
// a record grows enough fields is the day it is the only thing standing between
// that record and no record.
func TestARecordWithTooManyFieldsIsStillARecord(t *testing.T) {
	defer unstrict()()
	payload := map[string]any{"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "exec"}
	for i := range 200 {
		payload[fmt.Sprintf("field_%03d", i)] = strings.Repeat("<", 400)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: config.MinRecordBytes}).
		Write(payload, Output{})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > config.MinRecordBytes {
		t.Errorf("the terminal reduction is %d bytes for a cap of %d", len(data), config.MinRecordBytes)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("the terminal reduction does not parse: %v", err)
	}
	if record["log_id"] != "2026-08-11T06:00:00Z-abcd000001" {
		t.Errorf("it does not say which record it was: %v", record)
	}
	if record["record_reduced"] != true {
		t.Error("it does not say that it is a reduction")
	}
}

// A value that will not marshal at all took the same path, and the stub's own
// marshal failed with it: what landed was "\n", a blank line, which a reader
// passes over in silence.  A record was gone with nothing to notice, which is
// the one outcome this package is for.
func TestAnUnmarshallableRecordStillWritesALine(t *testing.T) {
	defer unstrict()()
	path := filepath.Join(t.TempDir(), "audit.log")
	NewLog(config.AuditConfig{LogPath: path, MaxRecordBytes: 1 << 20}).Write(map[string]any{
		"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "exec",
		// A channel marshals to an error, whatever else is in the record.
		"broken": make(chan int),
	}, Output{})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(strings.TrimSpace(string(data))) == 0 {
		t.Fatal("a blank line was written, which a reader skips without saying so")
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatalf("what was written does not parse: %q", data)
	}
	if got, _ := record["log_id"].(string); !strings.Contains(got, "abcd000001") {
		t.Errorf("the line does not say which record it was: %s", data)
	}
}

// clamp counts in encoded bytes and appends a marker, so an output of
// escape-heavy bytes comes back longer in raw ones than it went in.  A record
// whose output was cut and does not say so reads as a complete one.
func TestAnOutputCutByAReductionSaysSoEvenWhenItGrew(t *testing.T) {
	log := NewLog(config.AuditConfig{
		LogPath:        filepath.Join(t.TempDir(), "audit.log"),
		MaxRecordBytes: config.MinRecordBytes,
	})
	// Twenty '<' are 20 raw bytes and 120 encoded, so the last reduction step
	// (a 64-byte ceiling) cuts them to nothing and leaves a 27-byte marker.
	output := strings.Repeat("<", 20)
	payload := map[string]any{"log_id": "cut", "op": "exec", "output": output}
	// Enough elsewhere that the record only fits at that last step.
	for i := range 40 {
		payload[fmt.Sprintf("field%02d", i)] = strings.Repeat("x", 300)
	}

	var record map[string]any
	if err := json.Unmarshal(log.encode(payload), &record); err != nil {
		t.Fatalf("what was encoded does not parse: %v", err)
	}
	if got, _ := record["output"].(string); got == output {
		t.Fatalf("the output was not cut, so this asserts nothing: %q", got)
	}
	if record["output_truncated"] != true {
		t.Errorf("the output was cut and the record does not say so: %+v", record)
	}
	// And says how much: the whole of it, measured without the marker that
	// replaced it.
	if dropped, _ := record["output_dropped"].(float64); int(dropped) != len(output) {
		t.Errorf("output_dropped = %v, want %d", record["output_dropped"], len(output))
	}
}

// The identity fields are bounded here too.  One route to the stub is the first
// marshal failing, which skips the reductions entirely, so nothing else has
// bounded them and a line built from them would be as long as they are.
func TestTheStubBoundsTheIdentityItKeeps(t *testing.T) {
	line := stubLine(map[string]any{
		"log_id": strings.Repeat("a", 10_000),
		"op":     strings.Repeat("b", 10_000),
		"peer":   strings.Repeat("c", 10_000),
	})
	if len(line) > config.MinRecordBytes {
		t.Errorf("the stub is %d bytes, past the smallest cap an operator can set "+
			"(%d)", len(line), config.MinRecordBytes)
	}
	var record map[string]any
	if err := json.Unmarshal(line, &record); err != nil {
		t.Fatalf("the stub does not parse: %q", line)
	}
	if record["record_reduced"] != true {
		t.Errorf("the stub does not say it was reduced: %+v", record)
	}
}
