package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
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

// A torn final line is what a concurrent append looks like, and must not hide
// the records before it.
func TestReadAuditLogSkipsUnparseableLines(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
		`{"log_id":"c","op":`,
	)
	records, _, err := readAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	if str(records[1], "log_id") != "b" {
		t.Errorf("second record is %q, want b", str(records[1], "log_id"))
	}
}

// [audit] max_record_bytes defaults far past bufio's 64KiB.
func TestReadAuditLogHandlesLongRecords(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"big","output":"`+strings.Repeat("x", 200_000)+`"}`,
		`{"log_id":"after"}`,
	)
	records, _, err := readAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2: a long record truncated the scan", len(records))
	}
	if str(records[1], "log_id") != "after" {
		t.Errorf("the record after a long one is %q, want after", str(records[1], "log_id"))
	}
}

// Says the log is absent rather than an ENOENT on a path the caller never
// named.
func TestReadAuditLogNamesAnAbsentLog(t *testing.T) {
	_, _, err := readAuditLog(filepath.Join(t.TempDir(), "nope.log"))
	if err == nil {
		t.Fatal("no error for an absent log")
	}
	if !strings.Contains(err.Error(), "no audit log at") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// rec is one record read back the way the command reads it.
func rec(t *testing.T, line string) map[string]any {
	t.Helper()
	records, _, err := readAuditLog(writeLog(t, line))
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	return records[0]
}

// plain is colour off, so the assertions are about content rather than escapes.
func plain(t *testing.T) palette  { return mustPalette(t, "never") }
func always(t *testing.T) palette { return mustPalette(t, "always") }

func mustPalette(t *testing.T, when string) palette {
	t.Helper()
	paint, err := newPalette(when)
	if err != nil {
		t.Fatal(err)
	}
	return paint
}

func TestSummariseReportsWhatRanAndHowItEnded(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"2026-08-08T20:15:03Z-a91f","op":"exec",`+
		`"cmd":["ansible-playbook","msmtp.yml"],"exit_code":0,"duration_sec":1.5,`+
		`"redactions":[{"token":"«SECRET:a»","count":2}]}`), plain(t))
	for _, want := range []string{"a91f", "exec", "exit 0", "1.50s", "2 redacted",
		"ansible-playbook msmtp.yml"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
	// The timestamp is a column of its own.
	if strings.Contains(line, "2026-08-08T20:15:03Z") {
		t.Errorf("summary repeats the timestamp inside the id: %s", line)
	}
}

// A redact runs no command, so it has no exit code, but the row still has to
// say something.
func TestSummariseSaysSomethingForARedact(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"2026-08-08T20:15:03Z-b1c2","op":"redact","input_bytes":1447,`+
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
	label, failed := outcome(rec(t, `{"log_id":"x","op":"exec","exit_code":0,"timed_out":true}`))
	if label != "timed out" || !failed {
		t.Errorf("outcome = (%q, %v), want (timed out, true)", label, failed)
	}
}

// Padding counts escape bytes as width.
func TestPaintOutcomePadsBeforeColouring(t *testing.T) {
	record := rec(t, `{"log_id":"x","op":"exec","exit_code":0}`)
	got := paintOutcome(record, always(t))
	if !strings.HasSuffix(got, "\x1b[0m") {
		t.Fatalf("padding landed outside the colour span: %q", got)
	}
	bare := strings.TrimSuffix(strings.TrimPrefix(got, "\x1b[32m"), "\x1b[0m")
	if len(bare) != len(paintOutcome(record, plain(t))) {
		t.Errorf("coloured field is a different width from the plain one: %q", got)
	}
}

// The listing prints the short form, so it has to be enough to ask with.
func TestMatchesIDAcceptsBothForms(t *testing.T) {
	record := rec(t, `{"log_id":"2026-08-08T20:15:03Z-a91f"}`)
	for _, want := range []string{"2026-08-08T20:15:03Z-a91f", "a91f"} {
		if !matchesID(record, want) {
			t.Errorf("matchesID rejected %q", want)
		}
	}
	if matchesID(record, "beef") {
		t.Error("matchesID accepted an id that is not this record's")
	}
}

// A redact record carries no started_at, and a row with no time cannot be
// placed.
func TestStartedAtFallsBackToTheLogID(t *testing.T) {
	at := startedAt(rec(t, `{"log_id":"2026-08-08T20:15:03Z-a91f","op":"redact"}`))
	if at.IsZero() {
		t.Fatal("no time recovered from the log_id")
	}
	if got := at.UTC().Format("2006-01-02T15:04:05Z"); got != "2026-08-08T20:15:03Z" {
		t.Errorf("startedAt = %s, want the instant in the log_id", got)
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

func TestHumanBytes(t *testing.T) {
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

func TestNewPaletteRejectsAnUnknownWhen(t *testing.T) {
	if _, err := newPalette("sometimes"); err == nil {
		t.Fatal("no error for --color=sometimes")
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

// -n bounds the listing.  Zero asks for no records, and a guard that skipped the
// trim for anything non-positive printed the whole log to someone who asked for
// none of it.
func TestTailRecords(t *testing.T) {
	records := []map[string]any{{"log_id": "a"}, {"log_id": "b"}, {"log_id": "c"}}
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
			var got []string
			for _, record := range tailRecords(records, tc.count) {
				got = append(got, record["log_id"].(string))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("tailRecords(%d) = %v, want %v", tc.count, got, tc.want)
			}
		})
	}
}

// A record's output is bounded by [audit] max_record_bytes, and JSON escaping
// multiplies it: '<' renders as "<", six bytes for one, so a brokered
// command emitting 1.4MiB of them writes an 8MiB line.  A reader with a ceiling
// does not lose that record alone.  It stops there, so every record before and
// after it goes unread too, which makes one command a way to blind the log.
//
// Measured against a live install: 1,300,000 bytes of '<' listed fine and
// 1,400,000 took the whole log out, past and future, by id and by listing.
func TestReadAuditLogSurvivesARecordNoCeilingWouldFit(t *testing.T) {
	// Well past any fixed buffer, and past what a Scanner allowed.
	huge := strings.Repeat(`<`, 1_600_000) // 9.6MB of escapes, 1.6MB decoded
	path := writeLog(t,
		`{"log_id":"before","op":"exec"}`,
		`{"log_id":"poison","op":"exec","output":"`+huge+`"}`,
		`{"log_id":"after","op":"exec"}`,
	)
	records, skipped, err := readAuditLog(path)
	if err != nil {
		t.Fatalf("one oversized record made the whole log unreadable: %v", err)
	}
	if skipped != 0 {
		t.Errorf("skipped %d lines, want 0: every line here parses", skipped)
	}
	var ids []string
	for _, record := range records {
		ids = append(ids, str(record, "log_id"))
	}
	if !slices.Equal(ids, []string{"before", "poison", "after"}) {
		t.Errorf("read %v, want the records before, at and after the oversized one", ids)
	}
}

// An interior line that does not parse is a record that was lost, which is the
// one thing this file exists not to do quietly.  A full disk cuts a write short
// and the next record appends to what landed, so one failure takes two records
// and a listing that said nothing would look complete.
func TestReadAuditLogCountsInteriorLinesItSkipped(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"torn","op":"exec","output":"ZZZ{"log_id":"eaten","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
	)
	records, skipped, err := readAuditLog(path)
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

// The final line is the one an append can be caught halfway through, so it is
// not evidence of anything and must not be reported as a loss.  What marks it is
// the missing newline: nothing finished writing it.
func TestReadAuditLogDoesNotCountALineStillBeingAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	body := `{"log_id":"a","op":"exec"}` + "\n" + `{"log_id":"b","op":`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	records, skipped, err := readAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d, want 0 for a torn final line", skipped)
	}
	if len(records) != 1 {
		t.Errorf("got %d records, want 1", len(records))
	}
}

// An op longer than its column ran into the one after it: `ask_approval` and
// its outcome printed as `ask_approvalrefused`, with every column past it
// shifted.  A row whose columns have merged is a row that is read wrong.
func TestSummariseKeepsTheColumnsApartForALongOp(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"2026-08-08T20:15:03Z-4e16","op":"ask_approval",`+
		`"approved":false,"cmd":["sudo","id","-un"]}`), plain(t))
	if strings.Contains(line, "ask_approvalrefused") {
		t.Errorf("op and outcome merged: %q", line)
	}
	if !strings.Contains(line, "ask_approval refused") {
		t.Errorf("summarise = %q, want the op and the outcome as separate columns", line)
	}
}

// A glued line that ends properly is the shape a full disk leaves: the torn
// record, then the next record appended straight onto it, terminated by that
// second write.  It is the last line in the file and it is still a record lost,
// so the missing newline is what excuses a line, not its position.
func TestReadAuditLogCountsAGluedFinalLine(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	body := `{"log_id":"a","op":"exec"}` + "\n" +
		`{"log_id":"torn","op":"exec","output":"ZZZ` +
		`{"log_id":"eaten","op":"exec"}` + "\n"
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	records, skipped, err := readAuditLog(path)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 1 {
		t.Errorf("skipped = %d, want 1: a terminated line that will not parse is a record gone", skipped)
	}
	if len(records) != 1 {
		t.Errorf("got %d records, want 1", len(records))
	}
}
