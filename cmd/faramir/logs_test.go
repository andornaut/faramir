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

// The log is appended to by a running daemon while this reads it, so a torn
// final line is ordinary. It must not hide the records before it.
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

// A record carries its command's output, up to [audit] max_record_bytes, whose
// default is far past bufio's 64KiB. A long record must not stop the scan.
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

// The message has to say the log is absent rather than report a bare ENOENT on
// a path the caller never named.
func TestReadAuditLogNamesAnAbsentLog(t *testing.T) {
	_, err := readAuditLog(filepath.Join(t.TempDir(), "nope.log"))
	if err == nil {
		t.Fatal("no error for an absent log")
	}
	if !strings.Contains(err.Error(), "no audit log at") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Colour off, so the assertions are about content rather than escapes.
func plain(t *testing.T) palette {
	t.Helper()
	paint, err := newPalette("never")
	if err != nil {
		t.Fatal(err)
	}
	return paint
}

func TestSummariseReportsWhatRanAndHowItEnded(t *testing.T) {
	records, err := readAuditLog(writeLog(t,
		`{"log_id":"2026-08-08T20:15:03Z-a91f","op":"exec","peer":"andornaut",`+
			`"cmd":["ansible-playbook","msmtp.yml"],"exit_code":0}`))
	if err != nil {
		t.Fatal(err)
	}
	line := summarise(records[0], plain(t))
	for _, want := range []string{"2026-08-08T20:15:03Z-a91f", "exec", "exit 0", "andornaut",
		"ansible-playbook msmtp.yml"} {
		if !strings.Contains(line, want) {
			t.Errorf("summary is missing %q: %s", want, line)
		}
	}
}

// A redact request runs no command, so it has no exit code and must not be
// reported as having exited 0.
func TestExitLabelBlankWithoutAnExitCode(t *testing.T) {
	records, err := readAuditLog(writeLog(t, `{"log_id":"x","op":"redact"}`))
	if err != nil {
		t.Fatal(err)
	}
	if got := exitLabel(records[0], plain(t)); strings.Contains(got, "exit") {
		t.Errorf("exitLabel = %q, want no exit for a record that ran nothing", got)
	}
}

// Counts, never values: the log records how often a token stood in, and that
// is what this has to render.
func TestRedactionCountsRenderTokensAndCounts(t *testing.T) {
	records, err := readAuditLog(writeLog(t,
		`{"log_id":"x","redactions":[{"token":"«SECRET:a»","count":2},{"token":"«SECRET:b»","count":1}]}`))
	if err != nil {
		t.Fatal(err)
	}
	got := redactionCounts(records[0])
	if got != "«SECRET:a»×2, «SECRET:b»×1" {
		t.Errorf("redactionCounts = %q", got)
	}
}

func TestNewPaletteRejectsAnUnknownWhen(t *testing.T) {
	if _, err := newPalette("sometimes"); err == nil {
		t.Fatal("no error for --color=sometimes")
	}
}

// https://no-color.org: the variable is honoured whatever its value, empty
// included, so a test that sets it to "1" would not catch reading the value.
func TestNoColorDisablesColourWhateverItsValue(t *testing.T) {
	t.Setenv("NO_COLOR", "")
	paint, err := newPalette("auto")
	if err != nil {
		t.Fatal(err)
	}
	if paint.on {
		t.Error("NO_COLOR set to empty did not disable colour")
	}
}

// --color=always is for piping into a pager that renders escapes, so it has to
// win over the terminal check that would otherwise turn colour off.
func TestColorAlwaysBeatsTheTerminalCheck(t *testing.T) {
	t.Setenv("NO_COLOR", "1")
	paint, err := newPalette("always")
	if err != nil {
		t.Fatal(err)
	}
	if !paint.on {
		t.Error("--color=always did not force colour on")
	}
	if !strings.Contains(paint.ok("x"), "\x1b[") {
		t.Error("colour is on but nothing was emitted")
	}
}

func TestTokenHighlightsEverySecretToken(t *testing.T) {
	paint, err := newPalette("always")
	if err != nil {
		t.Fatal(err)
	}
	got := paint.token("a «SECRET:one» b «SECRET:two» c")
	if strings.Count(got, "\x1b[35m") != 2 {
		t.Errorf("expected both tokens highlighted: %q", got)
	}
	// The surrounding text has to survive intact, escapes aside.
	for _, want := range []string{"a ", " b ", " c"} {
		if !strings.Contains(got, want) {
			t.Errorf("text around the tokens was lost: %q", got)
		}
	}
}

// An unterminated token is what a record truncated mid-token looks like. It
// must come back whole rather than being swallowed by the search for the close.
func TestTokenLeavesAnUnterminatedTokenAlone(t *testing.T) {
	paint, err := newPalette("always")
	if err != nil {
		t.Fatal(err)
	}
	if got := paint.token("tail «SECRET:trunc"); got != "tail «SECRET:trunc" {
		t.Errorf("token mangled an unterminated token: %q", got)
	}
}
