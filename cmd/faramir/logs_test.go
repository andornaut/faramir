package main

import (
	"os"
	"path/filepath"
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
	records, err := readAuditLog(path)
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
	records, err := readAuditLog(path)
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
	_, err := readAuditLog(filepath.Join(t.TempDir(), "nope.log"))
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
	records, err := readAuditLog(writeLog(t, line))
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
