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
	atLimit(t, 1<<16)
	log := NewLog(config.AuditConfig{LogPath: path})

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
	atLimit(t, limit)
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(dir, "audit.log"),
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

// One record is one line, and no line exceeds max_record_bytes, counted in the
// bytes the line spends rather than the bytes a command wrote.  The table is
// what a command can choose from: '<' and a C0 control each cost six as JSON,
// so a cap counted before encoding is one whose meaning the command picks.
func TestNoRecordExceedsTheCapWhateverACommandPrints(t *testing.T) {
	const limit = 64 * 1024
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
			atLimit(t, limit)
			NewLog(config.AuditConfig{LogPath: path}).
				Write(map[string]any{"log_id": "x", "op": "run"}, Output{Text: tc.output})

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if len(data) > limit {
				t.Errorf("the record is %d bytes for a limit of %d", len(data), limit)
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
	const limit = 64 * 1024
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, limit)
	atLimit(t, 64*1024)
	NewLog(config.AuditConfig{LogPath: path}).Write(map[string]any{
		"log_id": "x", "op": "run",
		"cmd": []string{"bash", "-c", strings.Repeat("<", 2_000_000)},
		"cwd": strings.Repeat("d", 100_000),
	}, Output{})

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > limit {
		t.Fatalf("the record is %d bytes for a limit of %d", len(data), limit)
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

// An id is distinct by construction.  Random bytes alone collide
// often enough to matter, and a lookup shows the first match and says nothing
// about the second.  Asked concurrently, because the counter that orders them
// is shared.
func TestLogIDsDoNotRepeatAcrossGoroutines(t *testing.T) {
	const workers, each = 8, 25_000
	ids := make(chan string, workers*each)
	var wg sync.WaitGroup
	for range workers {
		wg.Go(func() {
			for range each {
				ids <- NewLogID()
			}
		})
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

// An append is exclusive, so concurrent writers cannot interleave
// and every line parses.  Two Logs over one path is what `faramir edit` beside a
// running broker looks like.
func TestConcurrentWritersLeaveEveryLineParseable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	cfg := config.AuditConfig{LogPath: path}

	const writers, each = 6, 40
	var wg sync.WaitGroup
	for w := range writers {
		wg.Go(func() {
			log := NewLog(cfg) // its own Log, as another process would have
			for i := range each {
				log.Write(map[string]any{
					"log_id": NewLogID(), "op": "run",
					"cmd": []string{"echo", fmt.Sprintf("w%d-i%d", w, i)},
				}, Output{Text: strings.Repeat("<", 20_000)})
			}
		})
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
	atLimit(t, 64*1024)
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(blocker, "audit.log"),
	})
	if reason := log.Unwritable(); reason == "" {
		t.Error("a log that cannot be opened reports as writable")
	}
}

// A record that does not fit is reduced, not discarded.  The ceiling reduce
// applies is counted in encoded bytes for the same reason the cap is: two
// hundred arguments of a thousand '<' each are 200KB raw, under any per-string
// limit worth having, and 1.2MB once encoded.
func TestALargeArgvKeepsTheRestOfTheRecord(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	args := make([]string, 0, 202)
	args = append(args, "bash", "-c")
	for range 200 {
		args = append(args, strings.Repeat("<", 1000))
	}
	atLimit(t, 262144)
	NewLog(config.AuditConfig{LogPath: path}).Write(map[string]any{
		"log_id": "x", "op": "run", "cmd": args, "cwd": "/srv/work",
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
	atLimit(t, 65536)
	NewLog(config.AuditConfig{LogPath: path}).Write(map[string]any{
		"log_id": "x", "op": "run", "cmd": []string{"printenv"}, "env_refs": refs,
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

// Unwritable is asked before every command, so it has to be about now rather
// than about startup: a log made unwritable afterwards must be noticed, or
// every command runs with its record going nowhere.  Posed as ENOTDIR rather
// than as a mode, root opening a file whatever its mode says.
func TestUnwritableNoticesALogThatBreaksAfterTheFirstWrite(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logdir")
	atLimit(t, 64*1024)
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(dir, "audit.log"),
	})

	log.Write(map[string]any{"log_id": "first", "op": "run"}, Output{})
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
// a reduced one.  A reserve fixed in advance instead lets the two add up past
// the cap, cutting the fields of every such command.
func TestALongArgvAndALongRunFitWithoutReducing(t *testing.T) {
	const limit = 1 << 20
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, limit)
	log := NewLog(config.AuditConfig{LogPath: path})

	// argv at what [server] max_request_bytes would let through, and output at
	// what Collector streams against, which is the pair that has to coexist.
	args := []string{"ansible-playbook", "--extra-vars", strings.Repeat("x", 200_000)}
	collector := NewCollector(log.OutputBudget())
	collector.Add(strings.Repeat("ok: [host.example.com]\n", 60_000))

	log.Write(map[string]any{
		"log_id": "x", "op": "run", "cmd": args, "cwd": "/srv/ansible",
		"exit_code": 0.0,
	}, collector.Output())

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) > limit {
		t.Fatalf("the record is %d bytes for a limit of %d", len(data), limit)
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
// becomes a ceiling on the record's own fields, deleting them until few enough
// are left and leaving something that reads as an ordinary complete record.
func TestReducingARecordKeepsEveryFieldOfIt(t *testing.T) {
	counts := make([]redact.Count, 0, 20_000)
	for i := range 20_000 {
		counts = append(counts, redact.Count{
			Token: fmt.Sprintf("«SECRET:team/service-%05d/password»", i), Count: 1,
		})
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, 1<<20)
	NewLog(config.AuditConfig{LogPath: path}).Write(map[string]any{
		"log_id": "x", "op": "run", "cmd": []string{"ansible-playbook", "site.yml"},
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

// Writing a record must not change what it is a record of: the fields the
// reductions cut are the caller's own live state, internal/escalation handing
// over the argv it holds for a run and going on rendering it into the question
// and every later record.
func TestWritingARecordLeavesTheCallersFieldsAlone(t *testing.T) {
	defer unstrict()()
	argv := []string{"ansible-playbook", "--extra-vars", strings.Repeat("x", 8*1024)}
	refs := map[string]string{"ROUTER_PW": "home/router/admin"}
	peer := map[string]any{"uid": 1001.0, "pid": 42.0}
	nested := []any{map[string]any{"deep": strings.Repeat("y", 8*1024)}}

	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, config.MinRecordBytes)
	NewLog(config.AuditConfig{LogPath: path}).
		Write(map[string]any{
			"log_id": "x", "op": "escalate", "cmd": argv,
			"env_refs": refs, "peer": peer, "nested": nested,
		}, Output{Text: strings.Repeat("z", 8*1024)})

	// The record was reduced, or this asserts nothing.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record map[string]any
	if err := json.Unmarshal(data, &record); err != nil {
		t.Fatal(err)
	}
	if reduced, _ := record["record_reduced"].(bool); !reduced {
		t.Fatalf("this record was not reduced, so it says nothing about reduction: %s", data)
	}

	if len(argv) != 3 || len(argv[2]) != 8*1024 {
		t.Errorf("the caller's argv was cut to %d args, the last %d bytes",
			len(argv), len(argv[len(argv)-1]))
	}
	if len(refs) != 1 || refs["ROUTER_PW"] != "home/router/admin" {
		t.Errorf("the caller's env_refs was rewritten: %v", refs)
	}
	if len(peer) != 2 || peer["uid"] != 1001.0 {
		t.Errorf("the caller's peer was rewritten: %v", peer)
	}
	inner, _ := nested[0].(map[string]any)
	deep, _ := inner["deep"].(string)
	if len(inner) != 1 || len(deep) != 8*1024 {
		t.Errorf("a nested map the caller owns was rewritten: %v", nested)
	}
}

// The identity stub is the backstop for a record that cannot be made to fit.
// Every caller-chosen field is bounded -- strings by encoded length, lists and
// maps by entry count -- so no record a caller composes reaches it: the
// smallest cap the config allows, against every field as large as anything
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
	args := make([]string, 0, 5_000)
	for range 5_000 {
		args = append(args, strings.Repeat("<", 2_000))
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, config.MinRecordBytes)
	NewLog(config.AuditConfig{LogPath: path}).
		Write(map[string]any{
			"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "run",
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
// rather than deleted as unreachable: it is what makes encode total.
func TestARecordWithTooManyFieldsIsStillARecord(t *testing.T) {
	defer unstrict()()
	payload := map[string]any{"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "run"}
	for i := range 200 {
		payload[fmt.Sprintf("field_%03d", i)] = strings.Repeat("<", 400)
	}
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, config.MinRecordBytes)
	NewLog(config.AuditConfig{LogPath: path}).
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

// A value that will not marshal at all takes the same path, and the stub's own
// marshal must not fail with it: a blank line is one a reader passes over in
// silence, so the record would be gone with nothing to notice.
func TestAnUnmarshallableRecordStillWritesALine(t *testing.T) {
	defer unstrict()()
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, 1<<20)
	NewLog(config.AuditConfig{LogPath: path}).Write(map[string]any{
		"log_id": "2026-08-11T06:00:00Z-abcd000001", "op": "run",
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
	atLimit(t, config.MinRecordBytes)
	log := NewLog(config.AuditConfig{
		LogPath: filepath.Join(t.TempDir(), "audit.log"),
	})
	// Twenty '<' are 20 raw bytes and 120 encoded, so the last reduction step
	// (a 64-byte ceiling) cuts them to nothing and leaves a 27-byte marker.
	output := strings.Repeat("<", 20)
	payload := map[string]any{"log_id": "cut", "op": "run", "output": output}
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

// Every record says when it happened in a field, so nothing has to take the
// instant out of the log_id, which no longer carries one.
func TestEveryRecordCarriesWhenItHappened(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	atLimit(t, 64*1024)
	log := NewLog(config.AuditConfig{LogPath: path})

	// A record with no time of its own: an escalation, a redact, an edit.
	log.Write(map[string]any{"log_id": NewLogID(), "op": "escalate"}, Output{})
	// And one that has one: an exec's started_at is its child's, which is not
	// when this line was written, so it is left alone and no at is added.
	log.Write(map[string]any{
		"log_id": NewLogID(), "op": "run", "started_at": 1786000000,
	}, Output{})

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(string(body)), "\n")
	records := make([]map[string]any, 0, len(lines))
	for _, line := range lines {
		var record map[string]any
		if err := json.Unmarshal([]byte(line), &record); err != nil {
			t.Fatalf("a record does not parse: %v", err)
		}
		records = append(records, record)
	}
	if len(records) != 2 {
		t.Fatalf("%d records, want 2", len(records))
	}

	at, ok := records[0]["at"].(float64)
	if !ok || at <= 0 {
		t.Errorf("a record with no started_at carries no at: %v", records[0])
	}
	if _, has := records[1]["at"]; has {
		t.Errorf("an exec's record was given an at beside its started_at: %v", records[1])
	}
	if records[1]["started_at"] != float64(1786000000) {
		t.Errorf("started_at = %v, want the one the caller passed", records[1]["started_at"])
	}
}

// And the id spends nothing on the instant: it is the clock, the nonce and the
// counter, in what a person can type off one terminal into another.
func TestALogIDIsShortAndCarriesNoTimestamp(t *testing.T) {
	id := NewLogID()
	if len(id) != idClockChars+6+4 {
		t.Errorf("log_id %q is %d characters, want %d", id, len(id), idClockChars+10)
	}
	if strings.ContainsAny(id, "-:TZ") {
		t.Errorf("log_id %q carries a timestamp's punctuation", id)
	}
	for _, r := range id {
		if !strings.ContainsRune(idAlphabet, r) {
			t.Errorf("log_id %q holds %q, which is outside the alphabet", id, r)
		}
	}
}
