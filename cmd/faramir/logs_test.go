package main

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
func TestTailRecordsSkipsUnparseableLines(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
		`{"log_id":"c","op":`,
	)
	records, _, err := tailRecords(path, 10)
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

// A record's line has no length a reader may refuse.  internal/audit holds one
// to [audit] max_record_bytes, and a ceiling here would be a second opinion
// about that -- one that withholds every record in the file rather than the one
// it could not read.
func TestTailRecordsSurvivesARecordNoCeilingWouldFit(t *testing.T) {
	huge := strings.Repeat(`<`, 1_600_000) // 9.6MB once escaped, past any buffer
	path := writeLog(t,
		`{"log_id":"before","op":"exec"}`,
		`{"log_id":"poison","op":"exec","output":"`+huge+`"}`,
		`{"log_id":"after","op":"exec"}`,
	)
	records, skipped, err := tailRecords(path, 10)
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

// -n bounds what is parsed, not only what is printed.  Parsing every record to
// throw all but a screenful away is what made a listing cost the size of the
// log; the last count lines are kept as bytes and parsed at the end.
func TestTailRecordsParsesOnlyWhatItWillShow(t *testing.T) {
	var lines []string
	for i := range 50 {
		lines = append(lines, fmt.Sprintf(`{"log_id":"id-%02d","op":"exec"}`, i))
	}
	// A line in the part that is skipped, which would fail to parse if it were
	// read: reaching it at all is the regression.
	lines[10] = `{"log_id":"unparseable","op":`
	path := writeLog(t, lines...)

	records, skipped, err := tailRecords(path, 3)
	if err != nil {
		t.Fatal(err)
	}
	if skipped != 0 {
		t.Errorf("skipped = %d: a line outside the tail was parsed", skipped)
	}
	var ids []string
	for _, record := range records {
		ids = append(ids, str(record, "log_id"))
	}
	if !slices.Equal(ids, []string{"id-47", "id-48", "id-49"}) {
		t.Errorf("got %v, want the last three", ids)
	}
}

// -n bounds the listing.  Zero asks for no records, and a guard that skipped the
// trim for anything non-positive printed the whole log to someone who asked for
// none of it.
func TestTailRecordsCounts(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
		`{"log_id":"c","op":"exec"}`,
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

// An interior line that does not parse is a record that was lost.  Since the
// writer takes back a write that lands short, one of these means the log was
// written by something else or damaged afterwards -- either way the listing must
// say so rather than look complete.
func TestTailRecordsCountsInteriorLinesItSkipped(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"torn","op":"exec","output":"ZZZ`+`{"log_id":"eaten","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
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
// it is.  "null" is the one that unmarshals without an error and leaves no
// record behind, so a reader testing only the error shows a listing that looks
// complete with a line missing from it, which is the failure reportSkipped
// exists to prevent.
func TestTailRecordsCountsEveryLineThatIsNotARecord(t *testing.T) {
	for _, line := range []string{"null", "false", "123", `"text"`, "[1]", "garbage"} {
		path := writeLog(t,
			`{"log_id":"a","op":"exec"}`,
			line,
			`{"log_id":"b","op":"exec"}`,
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
// not evidence of anything.  What marks it is the missing newline: nothing
// finished writing it.
func TestTailRecordsDoesNotCountALineStillBeingAppended(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	body := `{"log_id":"a","op":"exec"}` + "\n" + `{"log_id":"b","op":`
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
		t.Errorf("got %d records, want 1", len(records))
	}
}

// findRecord keeps the match and nothing else, so a lookup costs the same on a
// log of any length.
func TestFindRecordTakesEitherFormOfTheID(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"2026-08-08T20:15:03Z-a91f000001","op":"exec"}`,
		`{"log_id":"2026-08-08T20:15:04Z-a91f000002","op":"exec"}`,
	)
	for _, id := range []string{"2026-08-08T20:15:04Z-a91f000002", "a91f000002"} {
		record, _, err := findRecord(path, id)
		if err != nil {
			t.Fatal(err)
		}
		if record == nil {
			t.Fatalf("no record found for %q", id)
		}
		if str(record, "log_id") != "2026-08-08T20:15:04Z-a91f000002" {
			t.Errorf("found %q for %q", str(record, "log_id"), id)
		}
	}
	record, _, err := findRecord(path, "nothing")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Errorf("found %v for an id that is not in the log", record)
	}
}

// Says the log is absent rather than an ENOENT on a path the caller never
// named.
func TestScanAuditLogNamesAnAbsentLog(t *testing.T) {
	_, _, err := tailRecords(filepath.Join(t.TempDir(), "nope.log"), 10)
	if err == nil {
		t.Fatal("no error for an absent log")
	}
	if !strings.Contains(err.Error(), "no audit log at") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// And says it for a count that asks for nothing too: "no records to show" on a
// host with no log at all reads as an empty log rather than an absent one, so
// the two cases stay distinct whatever -n was passed.
func TestAnAbsentLogIsNamedEvenWhenNothingWasAskedFor(t *testing.T) {
	_, _, err := tailRecords(filepath.Join(t.TempDir(), "nope.log"), 0)
	if err == nil {
		t.Fatal("no error for an absent log")
	}
	if !strings.Contains(err.Error(), "no audit log at") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// The third case of an empty listing, after an absent log and an empty one:
// nothing was asked for.  Reporting that as "holds no records" is a claim about
// the host, and the log named there may be full of them.
func TestEmptyReasonSeparatesAskingForNoneFromHavingNone(t *testing.T) {
	for _, count := range []int{0, -1, -5} {
		got := emptyReason("/var/log/faramir/audit.log", count)
		if !strings.Contains(got, fmt.Sprintf("-n %d", count)) {
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

// A refused request never reached a command, so it has no exit code.  The
// listing has to say so: the alternative renders it as a command that ran and
// produced nothing, which is a different event.
func TestOutcomeReportsTheRefusalCode(t *testing.T) {
	for _, code := range []string{"bad_request", "unknown_secret", "busy",
		"forbidden", "no_secrets", "too_large", "not_quiescent", "no_audit"} {
		record := rec(t, `{"log_id":"x","op":"exec","cmd":["/bin/true"],`+
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
// spawned.  Neither carries an exit code either.
func TestOutcomeReportsAFailureWithNoExitCode(t *testing.T) {
	for _, body := range []string{
		`{"log_id":"x","op":"exec","cmd":["/bin/nope"],"error":"no such program"}`,
		`{"log_id":"x","op":"exec","cmd":["/bin/sh"],"started_at":1786000000,` +
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
	label, failed := outcome(rec(t, `{"log_id":"x","op":"exec","exit_code":0,"duration_sec":1}`))
	if label != "exit 0 1.00s" || failed {
		t.Errorf("outcome = (%q, %v), want (exit 0 1.00s, false)", label, failed)
	}
	if label, failed := outcome(rec(t, `{"log_id":"x","op":"redact","input_bytes":10}`)); label != "" || failed {
		t.Errorf("a redact was given an outcome: (%q, %v)", label, failed)
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

// The same for the outcome column, which holds a refusal code and so can be
// wider than the column: approval_in_progress is 20 against a 16-wide column.
// The row shifts, which is legible; the columns merging is not.
func TestSummariseKeepsTheColumnsApartForALongRefusalCode(t *testing.T) {
	line := summarise(rec(t, `{"log_id":"2026-08-08T20:15:03Z-4e16","op":"exec",`+
		`"refused":"approval_in_progress","cmd":["sudo","id","-un"]}`), plain(t))
	if !regexp.MustCompile(`approval_in_progress +sudo id -un`).MatchString(line) {
		t.Errorf("summarise = %q, want the code and the command as separate columns", line)
	}
}

// The ring grows to what the log holds rather than to what -n asked for.  Sized
// up front, `-n` was an allocation the caller named: a number the flag accepts,
// times a slice header, before a single line had been read.
func TestTailRecordsDoesNotAllocateWhatWasAskedFor(t *testing.T) {
	path := writeLog(t,
		`{"log_id":"a","op":"exec"}`,
		`{"log_id":"b","op":"exec"}`,
	)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	records, _, err := tailRecords(path, 500_000_000)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 {
		t.Fatalf("got %d records, want 2", len(records))
	}
	// A slice header is 24 bytes, so the old form wanted 12GB here.  Anything in
	// the megabytes means the count was allocated rather than the log.
	if grew := after.TotalAlloc - before.TotalAlloc; grew > 8<<20 {
		t.Errorf("reading two records with -n 500000000 allocated %d bytes", grew)
	}
}
