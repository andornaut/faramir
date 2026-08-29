package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/protocol"
)

func writeLog(t *testing.T, lines ...string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.log")
	body := strings.Join(lines, "\n") + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

// A record's line has no length a reader may refuse. internal/audit holds one
// to the record cap, and a ceiling here would be a second opinion
// about that: one that withholds every record in the file rather than the one
// it could not read.
func TestTailRecordsSurvivesARecordNoCeilingWouldFit(t *testing.T) {
	huge := strings.Repeat(`<`, 1_600_000) // 9.6MB once escaped, past any buffer
	path := writeLog(t,
		`{"log_id":"before","op":"run"}`,
		`{"log_id":"poison","op":"run","output":"`+huge+`"}`,
		`{"log_id":"after","op":"run"}`,
	)
	records, skipped, err := tailRecords(path, 10)
	if err != nil {
		t.Fatalf("one oversized record made the whole log unreadable: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped %d lines, want 0: every line here parses", skipped)
	}
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, str(record, "log_id"))
	}
	if !slices.Equal(ids, []string{"before", "poison", "after"}) {
		t.Errorf("read %v, want the records before, at and after the oversized one", ids)
	}
}

// --count bounds what is parsed, not only what is printed: the last count lines
// are kept as bytes and parsed at the end, so a listing does not cost the size
// of the log.
func TestTailRecordsParsesOnlyWhatItWillShow(t *testing.T) {
	lines := make([]string, 0, 50)
	for i := range 50 {
		lines = append(lines, fmt.Sprintf(`{"log_id":"id-%02d","op":"run"}`, i))
	}
	// A line in the part that is skipped, which would fail to parse if it were
	// read: reaching it at all is the failure.
	lines[10] = `{"log_id":"unparseable","op":`
	path := writeLog(t, lines...)

	records, skipped, err := tailRecords(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d: a line outside the tail was parsed", skipped)
	}
	ids := make([]string, 0, len(records))
	for _, record := range records {
		ids = append(ids, str(record, "log_id"))
	}
	if !slices.Equal(ids, []string{"id-47", "id-48", "id-49"}) {
		t.Errorf("got %v, want the last three", ids)
	}
}

// --count bounds the listing. Zero asks for no records, so the trim has to
// apply to a non-positive count as well: skipping it there prints the whole log
// to someone who asked for none of it.
func TestTailRecordsCounts(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"run"}`,
		`{"log_id":"b","op":"run"}`,
		`{"log_id":"c","op":"run"}`,
	)
	for _, tc := range []struct {
		name  string
		count int
		want  []string
	}{
		{"zero asks for nothing", 0, nil},
		{"a negative count asks for nothing", -1, nil},
		{"one takes the last", 1, []string{"c"}},
		{"two take the last two", 2, []string{"b", "c"}},
		{"the whole log", 3, []string{"a", "b", "c"}},
		{"more than there are is not an error", 99, []string{"a", "b", "c"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			records, _, err := tailRecords(path, tc.count)
			if err != nil {
				t.Fatal(err)
			}
			var got []string
			for _, record := range records {
				got = append(got, str(record, "log_id"))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("tailRecords(%d) = %v, want %v", tc.count, got, tc.want)
			}
		})
	}
}

// An interior line that does not parse is a record that was lost. The writer
// takes back a write that lands short, so one of these means the log was
// written by something else or damaged afterwards, and either way the listing
// must say so rather than look complete.
func TestTailRecordsCountsInteriorLinesItSkipped(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"run"}`,
		`{"log_id":"torn","op":"run","output":"ZZZ`+`{"log_id":"eaten","op":"run"}`,
		`{"log_id":"b","op":"run"}`,
	)
	records, skipped, err := tailRecords(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1: the glued line is a record nobody will see", skipped)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
}

// Every line that ends properly and yields no record is counted, whatever shape
// it is. "null" is the one that unmarshals without an error and leaves no
// record behind, so a reader testing only the error shows a listing that looks
// complete with a line missing from it, which is the failure reportSkipped
// exists to prevent.
func TestTailRecordsCountsEveryLineThatIsNotARecord(t *testing.T) {
	for _, line := range []string{"null", "false", "123", `"text"`, "[1]", "garbage"} {
		path := writeLog(t,
			`{"log_id":"a","op":"run"}`,
			line,
			`{"log_id":"b","op":"run"}`,
		)
		records, skipped, err := tailRecords(path, 10)
		if err != nil {
			t.Fatal(err)
		}
		if skipped != 1 {
			t.Errorf("skipped = %d for a line of %s, want 1", skipped, line)
		}
		if len(records) != 2 {
			t.Errorf("got %d records around a line of %s, want 2", len(records), line)
		}
	}
}

// The final line is the one an append can be caught halfway through, so it is
// not evidence of anything and must not hide the records before it. What marks
// it is the missing newline: nothing finished writing it.
func TestTailRecordsDoesNotCountALineStillBeingAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	body := `{"log_id":"a","op":"run"}` + "\n" + `{"log_id":"b","op":`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	records, skipped, err := tailRecords(path, 10)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 for a line still being appended", skipped)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	if str(records[0], "log_id") != "a" {
		t.Errorf("the record kept is %q, want a", str(records[0], "log_id"))
	}
}

// findRecord scans the log and keeps the match and nothing else, so a lookup
// costs the same on a log of any length.
func TestFindRecordScansForTheMatchingLine(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"w5vq7dbf000001","op":"run"}`,
		`{"log_id":"w5vq7dbg000002","op":"run"}`,
	)
	record, _, err := findRecord(path, "w5vq7dbg000002")
	if err != nil {
		t.Fatal(err)
	}
	if record == nil {
		t.Fatal("no record found")
	}
	if str(record, "log_id") != "w5vq7dbg000002" {
		t.Errorf("found %q, want the second record", str(record, "log_id"))
	}

	// Nothing, rather than the first line or an error: an id nobody wrote is a
	// question with an answer.
	record, _, err = findRecord(path, "nothing")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Errorf("found %v for an id that is not in the log", record)
	}
}

// appendLog adds lines to a log that is already there, the way the broker does:
// one record per line, opened per write.
func appendLog(t *testing.T, path string, lines ...string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	for _, line := range lines {
		if _, err := fh.WriteString(line + "\n"); err != nil {
			t.Fatal(err)
		}
	}
}

// appendPartial adds bytes with no newline after them: a record caught halfway
// through being written.
func appendPartial(t *testing.T, path, text string) {
	t.Helper()
	fh, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = fh.Close() }()
	if _, err := fh.WriteString(text); err != nil {
		t.Fatal(err)
	}
}

// drained is the log_ids a pass over the follower yields.
func drained(t *testing.T, f *follower) []string {
	t.Helper()
	var ids []string
	if err := f.drain(func(line []byte) {
		record, _ := parseLine(line)
		ids = append(ids, str(record, "log_id"))
	}); err != nil {
		t.Fatal(err)
	}
	return ids
}

// The point of --watch: the backlog and the records that arrive after it come
// through one reader, positioned where the backlog ended. A second reader
// opened afterwards would show a record written in between twice, or not at all.
func TestFollowerShowsWhatArrivesAfterTheBacklog(t *testing.T) {
	path := writeLog(t, `{"log_id":"a","op":"run"}`, `{"log_id":"b","op":"run"}`)
	f, err := openFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()

	backlog := newLineRing(1)
	if err := f.drain(backlog.add); err != nil {
		t.Fatal(err)
	}
	records, _ := parseLines(backlog.ordered())
	if len(records) != 1 || str(records[0], "log_id") != "b" {
		t.Fatalf("backlog = %v, want the last record only", records)
	}

	appendLog(t, path, `{"log_id":"c","op":"run"}`)
	if ids := drained(t, f); !slices.Equal(ids, []string{"c"}) {
		t.Errorf("the pass after the backlog yielded %v, want the appended record alone", ids)
	}
	if ids := drained(t, f); ids != nil {
		t.Errorf("a pass over an unchanged log yielded %v, want nothing", ids)
	}
}

// A record caught midway through its append is held, not shown and not counted
// as lost: the rest of the line is coming, and half a record parses as no
// record. A listing hands that line over instead, being a reading of the file
// as it stands.
func TestFollowerHoldsALineStillBeingAppended(t *testing.T) {
	path := writeLog(t, `{"log_id":"a","op":"run"}`)
	f, err := openFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	drained(t, f)

	appendPartial(t, path, `{"log_id":"b","op":`)
	if ids := drained(t, f); ids != nil {
		t.Errorf("a half-written record was shown as %v", ids)
	}
	appendLog(t, path, `"exec"}`)
	if ids := drained(t, f); !slices.Equal(ids, []string{"b"}) {
		t.Errorf("the finished record came out as %v, want it whole once its line ended", ids)
	}
}

// logrotate renames the log and the broker creates the next one by writing to
// it, so a watcher has to notice that the path names a different file. What was
// written to the old one before the rename is drained first: those are records.
func TestFollowerReopensAfterRotation(t *testing.T) {
	path := writeLog(t, `{"log_id":"a","op":"run"}`)
	f, err := openFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	drained(t, f)

	appendLog(t, path, `{"log_id":"last-before-rotation","op":"run"}`)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"last-before-rotation"}) {
		t.Errorf("the rotated file's last records came out as %v, want them before the switch", ids)
	}
	rotated, err := f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Error("a path with no file at it was read as a rotation: that is the gap " +
			"between the rename and the next record, and the file being read is still the log")
	}

	appendLog(t, path, `{"log_id":"first-after-rotation","op":"run"}`)
	rotated, err = f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("a new file at the path was not read as a rotation")
	}
	if err := f.reopen(); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"first-after-rotation"}) {
		t.Errorf("after reopening, the new log read as %v", ids)
	}
}

// The other way the file stops being the log: emptied in place, leaving the
// reader past the end of what it now holds. Nothing the install does this, but
// a watcher that keeps reading from an offset the file no longer reaches shows
// nothing again, ever.
func TestFollowerNoticesTheLogEmptiedInPlace(t *testing.T) {
	path := writeLog(t, `{"log_id":"a","op":"run"}`)
	f, err := openFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	drained(t, f)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	rotated, err := f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Error("a log emptied in place was not noticed")
	}
}

// A watcher started before the first brokered command has no file to read: the
// broker creates the log by writing its first record. Waiting for it is the
// whole of --watch on a fresh host, so a follower opens detached rather than
// failing, reads nothing while it is, and attaches when the log appears.
func TestFollowerWaitsForALogThatIsNotThereYet(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	f, err := openFollower(path)
	if err != nil {
		t.Fatalf("openFollower on a path with no log = %v, want a detached follower", err)
	}
	defer f.close()
	if f.following() {
		t.Error("a follower with no file at its path reports it is following one")
	}
	if ids := drained(t, f); ids != nil {
		t.Errorf("a detached follower yielded %v", ids)
	}
	rotated, err := f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Error("a path that still has no file read as a rotation")
	}

	appendLog(t, path, `{"log_id":"first","op":"run"}`)
	rotated, err = f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("the log appearing was not noticed, so nothing would ever attach to it")
	}
	if err := f.reopen(); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"first"}) {
		t.Errorf("the first record read as %v, want it whole once the log existed", ids)
	}
}

// The file can go between the stat that reports a rotation and the open that
// follows it: a second logrotate pass, or a hand removing it. That leaves the
// follower detached rather than holding a closed reader, so the watcher waits
// out the gap instead of failing on every pass after it.
func TestFollowerSurvivesAReopenThatFindsNothing(t *testing.T) {
	path := writeLog(t, `{"log_id":"a","op":"run"}`)
	f, err := openFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.close()
	drained(t, f)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := f.reopen(); !os.IsNotExist(err) {
		t.Fatalf("reopen with no file at the path = %v, want a not-exist error", err)
	}
	if ids := drained(t, f); ids != nil {
		t.Errorf("a pass after the failed reopen yielded %v", ids)
	}

	appendLog(t, path, `{"log_id":"b","op":"run"}`)
	rotated, err := f.rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("the log coming back was not noticed")
	}
	if err := f.reopen(); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"b"}) {
		t.Errorf("after the log came back the watcher read %v, want it to carry on", ids)
	}
}

// A log-id names one record that is already written, so there is nothing to
// wait for. Blocked before the root check and before the config is read, so an
// operator who typed both is told which is wrong rather than told to use sudo
// and then told this.
func TestLogsRefusesAWatchWithALogID(t *testing.T) {
	f := logsFlags{when: "never", watch: true, count: 20}
	said, code := captureStderr(t, func() int { return runLogs(f, []string{"a"}) })
	if code != 2 {
		t.Errorf("faramir logs --watch w5vq7dbg000002 = %d, want 2 (usage)", code)
	}
	// Which of the two to drop: a refusal that only says the pair is wrong
	// leaves the caller to guess, and the guess costs another run as root.
	if !strings.Contains(said, "takes no log-id") {
		t.Errorf("the refusal does not say which half is wrong: %q", said)
	}
}

// An unknown --color is refused before anything is read, so it is a usage error
// rather than the exit 1 that says the log could not be reached. Decided in
// runLogs and not only in newPalette: the status the shell sees is what tells a
// script it was invoked wrongly.
func TestLogsRefusesAnUnknownColour(t *testing.T) {
	f := logsFlags{when: "pink", count: 20}
	said, code := captureStderr(t, func() int { return runLogs(f, nil) })
	if code != 2 {
		t.Errorf("faramir logs --color pink = %d, want 2 (usage)", code)
	}
	if !strings.Contains(said, "pink") {
		t.Errorf("the refusal does not name what was passed: %q", said)
	}
}

// Says the log is absent rather than an ENOENT on a path the caller never
// named, and says it whatever --count was passed: "no records to show" on a
// host with no log at all reads as an empty log rather than an absent one.
func TestTailRecordsNamesAnAbsentLog(t *testing.T) {
	for _, count := range []int{10, 0} {
		_, _, err := tailRecords(filepath.Join(t.TempDir(), "nope.log"), count)
		if err == nil {
			t.Fatalf("no error for an absent log at --count %d", count)
		}
		if !strings.Contains(err.Error(), "no audit log at") {
			t.Errorf("unhelpful error at --count %d: %v", count, err)
		}
	}
}

// The third case of an empty listing, after an absent log and an empty one:
// nothing was asked for. Reporting that as "holds no records" is a claim about
// the host, and the log named there may be full of them.
func TestEmptyReasonSeparatesAskingForNoneFromHavingNone(t *testing.T) {
	for _, count := range []int{0, -1, -5} {
		got := emptyReason("/var/log/faramir/audit.log", count)
		if !strings.Contains(got, fmt.Sprintf("--count %d", count)) {
			t.Errorf("emptyReason(%d) = %q, want it to name the count that asked for nothing", count, got)
		}
		if strings.Contains(got, "holds no records") {
			t.Errorf("emptyReason(%d) = %q: a count of none was reported as a log of none", count, got)
		}
	}
	got := emptyReason("/var/log/faramir/audit.log", 20)
	if !strings.Contains(got, "/var/log/faramir/audit.log holds no records") {
		t.Errorf("emptyReason(20) = %q, want the log named as empty", got)
	}
}

// rec is one record read back the way the command reads it.
func rec(t *testing.T, line string) map[string]any {
	t.Helper()
	records, _, err := tailRecords(writeLog(t, line), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	return records[0]
}

// plain is colour off, so the assertions are about content rather than escapes.
func plain(t *testing.T) palette {
	t.Helper()
	return mustPalette(t, "never")
}

func always(t *testing.T) palette {
	t.Helper()
	return mustPalette(t, "always")
}

func mustPalette(t *testing.T, when string) palette {
	t.Helper()
	paint, err := newPalette(when)
	if err != nil {
		t.Fatal(err)
	}
	return paint
}

func TestSummariseReportsWhatRanAndHowItEnded(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf00a91f","op":"run",`+
		`"cmd":["ansible-playbook","msmtp.yml"],"exit_code":0,"duration_sec":1.5,`+
		`"redactions":[{"token":"«SECRET:a»","count":2}]}`), plain(t))
	// The whole id, which is what a lookup takes: asserting on its tail would
	// pass a row that printed only the tail.
	for _, want := range []string{"w5vq7dbf00a91f", "run", "exit 0", "1.50s", "2 redacted",
		"ansible-playbook msmtp.yml"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
}

// A redact runs no command, so it has no exit code, but the row still has to
// say something.
func TestSummariseSaysSomethingForARedact(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf00b1c2","op":"redact","input_bytes":1447,`+
		`"redactions":[{"token":"«SECRET:a»","count":1}]}`), plain(t))
	if strings.Contains(line, "exit") {
		t.Errorf("a record that ran nothing was given an exit: %s", line)
	}
	for _, want := range []string{"1 redacted", "1.4 KiB in"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
}

// A timed-out command's exit code says nothing useful.
func TestOutcomeReportsATimeout(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0,"timed_out":true}`))
	if label != "timed out" || !failed {
		t.Errorf("outcome = (%q, %v), want (timed out, true)", label, failed)
	}
}

// A run killed because its caller went. The record is the whole of what is
// reported -- the response went to a connection that had closed -- and read as
// a bare "exit 137" it says a signal without saying who sent it, which is the
// one thing this row is for.
func TestOutcomeReportsACallerThatWent(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":137,"abandoned":true}`))
	if label != "caller gone" || !failed {
		t.Errorf("outcome = (%q, %v), want (caller gone, true)", label, failed)
	}
	// And a timeout is still a timeout: both end in a killed process, and only
	// one of them is the command taking too long.
	label, _ = outcome(rec(t, `{"log_id":"x","op":"run","exit_code":137,"timed_out":true}`))
	if label != "timed out" {
		t.Errorf("outcome = %q, want timed out", label)
	}
	// An ordinary ending is untouched.
	if label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0}`)); failed ||
		!strings.Contains(label, "0") {
		t.Errorf("outcome = (%q, %v), want a clean exit", label, failed)
	}
}

// A refused request never reached a command, so it has no exit code. The
// listing has to say so: the alternative renders it as a command that ran and
// produced nothing, which is a different event.
func TestOutcomeReportsTheRefusalCode(t *testing.T) {
	for _, code := range []string{"bad_request", "unknown_secret", "busy",
		"forbidden", "no_secrets", "too_large", "not_quiescent", "no_audit"} {
		record := rec(t, `{"log_id":"x","op":"run","cmd":["/bin/true"],`+
			`"refused":"`+code+`","error":"why"}`)
		label, failed := outcome(record)
		if label != code || !failed {
			t.Errorf("outcome = (%q, %v), want (%s, true)", label, failed, code)
		}
		// The code is what the caller was answered with, so the row can be
		// scanned for it and matched against what the agent reported.
		if line := summarise(record, plain(t)); !strings.Contains(line, code) {
			t.Errorf("the listing does not name the refusal: %s", line)
		}
	}
}

// The broker also records a request that failed without being refused: the
// program would not resolve, or the executor was lost after the child was
// spawned. Neither carries an exit code either.
func TestOutcomeReportsAFailureWithNoExitCode(t *testing.T) {
	for _, body := range []string{
		`{"log_id":"x","op":"run","cmd":["/bin/nope"],"error":"no such program"}`,
		`{"log_id":"x","op":"run","cmd":["/bin/sh"],"started_at":1786000000,` +
			`"error":"executor: connection reset"}`,
	} {
		label, failed := outcome(rec(t, body))
		if label != "failed" || !failed {
			t.Errorf("outcome = (%q, %v), want (failed, true): %s", label, failed, body)
		}
	}
}

// A record that ran keeps its exit code, and a redact has no outcome at all:
// neither is what the two branches above are for.
func TestOutcomeLeavesTheOrdinaryRecordsAlone(t *testing.T) {
	label, failed := outcome(rec(t, `{"log_id":"x","op":"run","exit_code":0,"duration_sec":1}`))
	if label != "exit 0 1.00s" || failed {
		t.Errorf("outcome = (%q, %v), want (exit 0 1.00s, false)", label, failed)
	}
	if label, failed := outcome(rec(t, `{"log_id":"x","op":"redact","input_bytes":10}`)); label != "" || failed {
		t.Errorf("a redact was given an outcome: (%q, %v)", label, failed)
	}
}

// Padding counts escape bytes as width.
func TestPaintOutcomePadsBeforeColouring(t *testing.T) {
	record := rec(t, `{"log_id":"x","op":"run","exit_code":0}`)
	got := paintOutcome(record, always(t))
	if !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("padding landed outside the colour span: %q", got)
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(got, "\x1b[32m"), "\x1b[0m")
	if len(bare) != len(paintOutcome(record, plain(t))) {
		t.Errorf("coloured field is a different width from the plain one: %q", got)
	}
}

// An id is what the listing prints, so it is enough to ask with.
func TestMatchesIDTakesTheIDAsPrinted(t *testing.T) {
	record := rec(t, `{"log_id":"w5vq7dbf000001"}`)
	if !matchesID(record, "w5vq7dbf000001") {
		t.Error("matchesID rejected the id as printed")
	}
	if matchesID(record, "w5vq7dbf000002") {
		t.Error("matchesID accepted an id that is not this record's")
	}
}

// peer is an object of pid, uid and gid; read as a string it renders as
// nothing.
func TestDescribePeerRendersTheObject(t *testing.T) {
	got := describePeer(rec(t, `{"log_id":"x","peer":{"pid":4390,"uid":0,"gid":0}}`))
	for _, want := range []string{"root", "uid 0", "pid 4390"} {
		if !strings.Contains(got, want) {
			t.Errorf("describePeer = %q, missing %q", got, want)
		}
	}
}

func TestHumanBytesScalesToTheLargestWholeUnit(t *testing.T) {
	for _, tc := range []struct {
		size int64
		want string
	}{
		{0, "0 B"},
		{512, "512 B"},
		{1447, "1.4 KiB"},
		{4 << 20, "4.0 MiB"},
	} {
		if got := humanBytes(tc.size); got != tc.want {
			t.Errorf("humanBytes(%d) = %q, want %q", tc.size, got, tc.want)
		}
	}
}

// Counts, never values.
func TestRedactionCountsRenderTokensAndCounts(t *testing.T) {
	got := redactionCounts(rec(t,
		`{"log_id":"x","redactions":[{"token":"«SECRET:a»","count":2},{"token":"«SECRET:b»","count":1}]}`))
	if got != "«SECRET:a»×2, «SECRET:b»×1" {
		t.Errorf("redactionCounts = %q", got)
	}
}

// https://no-color.org: honoured whatever its value, empty included.
func TestNoColorDisablesColourWhateverItsValue(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	if mustPalette(t, "auto").on {
		t.Error("NO_COLOR set to empty did not disable colour")
	}
}

// --color=always is for piping into a pager, so it beats the terminal check.
func TestColorAlwaysBeatsTheTerminalCheck(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	paint := always(t)
	if !paint.on {
		t.Error("--color=always did not force colour on")
	}
	if !strings.Contains(paint.ok("x"), "\x1b[") {
		t.Error("colour is on but nothing was emitted")
	}
}

func TestTokenHighlightsEverySecretToken(t *testing.T) {
	got := always(t).token("a «SECRET:one» b «SECRET:two» c")
	if strings.Count(got, "\x1b[35m") != 2 {
		t.Errorf("expected both tokens highlighted: %q", got)
	}
	// The surrounding text survives intact, escapes aside.
	for _, want := range []string{"a ", " b ", " c"} {
		if !strings.Contains(got, want) {
			t.Errorf("text around the tokens was lost: %q", got)
		}
	}
}

// A record truncated mid-token must come back whole rather than be swallowed by
// the search for the close.
func TestTokenLeavesAnUnterminatedTokenAlone(t *testing.T) {
	if got := always(t).token("tail «SECRET:trunc"); got != "tail «SECRET:trunc" {
		t.Errorf("token mangled an unterminated token: %q", got)
	}
}

// An op longer than its column must not run into the one after it: merged as
// `run_startedstarted`, with every column past it shifted, the row is read
// wrong.
func TestSummariseKeepsTheColumnsApartForALongOp(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf004e16","op":"run_started",`+
		`"approved":false,"cmd":["sudo","id","-un"]}`), plain(t))
	if strings.Contains(line, "run_startedstarted") {
		t.Errorf("op and outcome merged: %q", line)
	}
	if !strings.Contains(line, "run_started started") {
		t.Errorf("summarise = %q, want the op and the outcome as separate columns", line)
	}
}

// opWidth is a number somebody has to keep true, and the case above proves only
// that one name fits: pad appends a space to anything already at the width, so
// an op as wide as its column shifts every column after it. logs.go names the
// ops it renders rather than importing them, and this is where the two meet.
func TestEveryOpFitsTheColumn(t *testing.T) {
	ops := append([]string{opRunStarted, opAdd, opEdit, opRemove, opReseal, opReader},
		protocol.Ops...)
	for _, op := range ops {
		t.Run(op, func(t *testing.T) {
			if len(op) >= opWidth {
				t.Errorf("op %q is %d wide and opWidth is %d, so it leaves no separating "+
					"space; raise opWidth past the longest op", op, len(op), opWidth)
			}
		})
	}
}

// The same for the outcome column, which holds a refusal code and so can be
// wider than the column: escalation_in_progress is 20 against a 16-wide column.
// The row shifts, which is legible; the columns merging is not.
func TestSummariseKeepsTheColumnsApartForALongRefusalCode(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"w5vq7dbf004e16","op":"run",`+
		`"refused":"escalation_in_progress","cmd":["sudo","id","-un"]}`), plain(t))
	if !regexp.MustCompile(`escalation_in_progress +sudo id -un`).MatchString(line) {
		t.Errorf("summarise = %q, want the code and the command as separate columns", line)
	}
}

// The ring grows to what the log holds rather than to what --count asked for.
// A slice header is 24 bytes, so sizing to the count up front wants 12GB for the
// number below, which the flag accepts and two records satisfy.
func TestTailRecordsDoesNotAllocateWhatWasAskedFor(t *testing.T) {
	const absurd = 500_000_000
	if got := ringCap(absurd); got != ringCapMax {
		t.Errorf("ringCap(%d) = %d, want it bounded at %d", absurd, got, ringCapMax)
	}
	// Under the bound the count still decides, so a small listing allocates once.
	if got := ringCap(3); got != 3 {
		t.Errorf("ringCap(3) = %d, want 3", got)
	}

	// And the bound does not cost the caller records: the ring grows past it.
	lines := make([]string, 0, ringCapMax+5)
	for i := range ringCapMax + 5 {
		lines = append(lines, fmt.Sprintf(`{"log_id":"id-%04d","op":"run"}`, i))
	}
	records, _, err := tailRecords(writeLog(t, lines...), absurd)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != len(lines) {
		t.Errorf("got %d records, want every one of the %d in the log", len(records), len(lines))
	}
}

// A run writes a pair sharing one log_id, so a lookup has to say which half it
// means: the ending where there is one, and the start where the command is still
// running.
func TestFindRecordPrefersTheEndingOverTheStart(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"w5vq7dbf000001","op":"run_started","cmd":["playbook"]}`,
		`{"log_id":"w5vq7dbf000001","op":"run","cmd":["playbook"],"exit_code":0}`,
		`{"log_id":"w5vq7dbh000002","op":"run_started","cmd":["still-going"]}`,
	)
	record, _, err := findRecord(path, "w5vq7dbf000001")
	if err != nil {
		t.Fatal(err)
	}
	if str(record, "op") != "run" {
		t.Errorf("looking up a finished command found the %q record, want the ending",
			str(record, "op"))
	}

	// And the start where that is all there is, rather than nothing: a command
	// still running is one an operator looks up while it runs.
	record, _, err = findRecord(path, "w5vq7dbh000002")
	if err != nil {
		t.Fatal(err)
	}
	if str(record, "op") != "run_started" {
		t.Errorf("looking up a running command found %q, want its start", str(record, "op"))
	}
}

// A command that has started and not ended reads as started. Blank in that
// column would render it as a command that ran and did nothing, which is the one
// reading the listing must not offer, and "running" would claim of a log read
// later that the command is still going.
func TestAStartedExecReadsAsStarted(t *testing.T) {
	label, failed := outcome(map[string]any{"op": "run_started", "cmd": []any{"playbook"}})
	if label != "started" {
		t.Errorf("outcome = %q, want started", label)
	}
	if failed {
		t.Error("a command that has only started is painted as a failure")
	}
}

// A question a human refused was judged; one that expired means nothing was
// watching. Rendered alike they read as the same event, and an operator scanning
// for "nobody was there" would find neither.
func TestEachAnswerReadsAsItsOwnEnding(t *testing.T) {
	for _, tc := range []struct {
		code   string
		want   string
		failed bool
	}{
		{escalation.CodeApproved, "approved", false},
		{escalation.CodeRejected, "rejected", true},
		{escalation.CodeExpired, "timed out", true},
		{escalation.CodeNotQuiescent, "not quiescent", true},
		{escalation.CodeRunEnded, "run ended", true},
		{escalation.CodeBrokerStopped, "broker stopped", true},
		// A code this reader does not know is printed rather than blanked: the log
		// is read by whatever version is installed, and a row saying nothing about
		// how a question ended is the one thing this column must not print.
		{"something_later", "something_later", true},
	} {
		t.Run(tc.code, func(t *testing.T) {
			label, failed := outcome(map[string]any{
				"op": "escalate", "approved": tc.code == escalation.CodeApproved,
				"outcome_code": tc.code, "outcome": "prose nobody selects on",
			})
			if label != tc.want {
				t.Errorf("outcome = %q, want %q", label, tc.want)
			}
			if failed != tc.failed {
				t.Errorf("failed = %v, want %v", failed, tc.failed)
			}
		})
	}
}

// A record written before the code existed still reads: the boolean is what it
// carried, and a listing over a log that spans an upgrade must not blank half of
// its rows.
func TestAnAnswerWithNoCodeStillReads(t *testing.T) {
	if label, failed := outcome(map[string]any{
		"op": "escalate", "approved": false, "outcome": "refused by root",
	}); label != "rejected" || !failed {
		t.Errorf("outcome = (%q, %v), want (rejected, true)", label, failed)
	}
}

// A lookup stops at the record it was asked for. Damage after it is damage in
// the way of some other question, and reporting it here says this record may be
// incomplete when it is not.
func TestFindRecordStopsAtTheEnding(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"w5vq7dbf000001","op":"run_started","cmd":["playbook"]}`,
		`{"log_id":"w5vq7dbf000001","op":"run","cmd":["playbook"],"exit_code":0}`,
		`{"log_id":"w5vq7dbh0000a91f0000`,
	)
	record, skipped, err := findRecord(path, "w5vq7dbf000001")
	if err != nil {
		t.Fatal(err)
	}
	if str(record, "op") != "run" {
		t.Errorf("found the %q record, want the ending", str(record, "op"))
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0: the damage is past the record asked for", skipped)
	}
}

// The time comes from the record, in whichever field it carries: started_at is
// an exec's child, at is everything else, and the log_id is only for a record an
// older broker wrote.
func TestTheTimeComesFromTheRecord(t *testing.T) {
	if got := startedAt(map[string]any{"started_at": 1786000000.0, "at": 1786009999.0}); got.Unix() != 1786000000 {
		t.Errorf("started_at = %v, want the child's own start to win", got.Unix())
	}
	if got := startedAt(map[string]any{"at": 1786009999.0}); got.Unix() != 1786009999 {
		t.Errorf("at = %v, want the record's own stamp", got.Unix())
	}
	if got := startedAt(map[string]any{"log_id": "w5vq7dbf000001"}); !got.IsZero() {
		t.Errorf("an id that carries no time produced %v", got)
	}
}
