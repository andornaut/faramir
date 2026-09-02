package auditview

// Reading records back: the tail, the search for one and the ring that bounds both.

import (
	"fmt"
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
	records, skipped, err := Tail(path, 10)
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

	records, skipped, err := Tail(path, 3)
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
			records, _, err := Tail(path, tc.count)
			if err != nil {
				t.Fatal(err)
			}
			got := make([]string, 0, len(records))
			for _, record := range records {
				got = append(got, str(record, "log_id"))
			}
			if !slices.Equal(got, tc.want) {
				t.Errorf("Tail(%d) = %v, want %v", tc.count, got, tc.want)
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
	records, skipped, err := Tail(path, 10)
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
		records, skipped, err := Tail(path, 10)
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
	records, skipped, err := Tail(path, 10)
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
	record, _, err := Find(path, "w5vq7dbg000002")
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
	record, _, err = Find(path, "nothing")
	if err != nil {
		t.Fatal(err)
	}
	if record != nil {
		t.Errorf("found %v for an id that is not in the log", record)
	}
}

// Says the log is absent rather than an ENOENT on a path the caller never
// named, and says it whatever --count was passed: "no records to show" on a
// host with no log at all reads as an empty log rather than an absent one.
func TestTailRecordsNamesAnAbsentLog(t *testing.T) {
	for _, count := range []int{10, 0} {
		_, _, err := Tail(filepath.Join(t.TempDir(), "nope.log"), count)
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
		got := EmptyReason("/var/log/faramir/audit.log", count)
		if !strings.Contains(got, fmt.Sprintf("--count %d", count)) {
			t.Errorf("emptyReason(%d) = %q, want it to name the count that asked for nothing", count, got)
		}
		if strings.Contains(got, "holds no records") {
			t.Errorf("emptyReason(%d) = %q: a count of none was reported as a log of none", count, got)
		}
	}
	got := EmptyReason("/var/log/faramir/audit.log", 20)
	if !strings.Contains(got, "/var/log/faramir/audit.log holds no records") {
		t.Errorf("emptyReason(20) = %q, want the log named as empty", got)
	}
}

// rec is one record read back the way the command reads it.
func rec(t *testing.T, line string) map[string]any {
	t.Helper()
	records, _, err := Tail(writeLog(t, line), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 {
		t.Fatalf("got %d records, want 1", len(records))
	}
	return records[0]
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
	records, _, err := Tail(writeLog(t, lines...), absurd)
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
	record, _, err := Find(path, "w5vq7dbf000001")
	if err != nil {
		t.Fatal(err)
	}
	if str(record, "op") != "run" {
		t.Errorf("looking up a finished command found the %q record, want the ending",
			str(record, "op"))
	}

	// And the start where that is all there is, rather than nothing: a command
	// still running is one an operator looks up while it runs.
	record, _, err = Find(path, "w5vq7dbh000002")
	if err != nil {
		t.Fatal(err)
	}
	if str(record, "op") != "run_started" {
		t.Errorf("looking up a running command found %q, want its start", str(record, "op"))
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
	record, skipped, err := Find(path, "w5vq7dbf000001")
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
