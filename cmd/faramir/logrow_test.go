package main

import (
	"strings"
	"testing"
	"time"
)

// The date header above each day's first row. The printer carries the last day
// it wrote, so a watcher left running prints a new header when the day turns
// under it rather than repeating one per row.
//
// Offsets rather than calendar dates: the header is formatted in the local zone,
// so what counts as a day boundary depends on where the test runs. Two instants
// 48 hours apart are different local days everywhere.

const aDay = 24 * time.Hour

func recordAt(offset time.Duration) map[string]any {
	// A fixed instant, so a run near midnight cannot move a record into the
	// neighbouring day.
	base := time.Unix(1_755_700_000, 0)
	return map[string]any{
		"started_at": float64(base.Add(offset).Unix()),
		"cmd":        []any{"true"},
	}
}

func headersPrinted(t *testing.T, records []map[string]any) (int, string) {
	t.Helper()
	out, _ := captureStdout(t, func() int {
		p := &logPrinter{paint: palette{}}
		for _, r := range records {
			p.row(r)
		}
		return 0
	})
	n := 0
	for line := range strings.SplitSeq(out, "\n") {
		// A header is the bare day; a row carries a time and the command as well.
		if _, err := time.Parse(dateLayout, strings.TrimSpace(line)); err == nil {
			n++
		}
	}
	return n, out
}

func TestRowPrintsOneDateHeaderPerDay(t *testing.T) {
	for _, tc := range []struct {
		name    string
		records []map[string]any
		want    int
	}{
		{"a single record gets one header",
			[]map[string]any{recordAt(0)}, 1},
		{"two records on one day share a header",
			[]map[string]any{recordAt(0), recordAt(0)}, 1},
		{"the day turning prints a second header",
			[]map[string]any{recordAt(0), recordAt(2 * aDay)}, 2},
		{"back to a day already printed prints it again",
			[]map[string]any{recordAt(0), recordAt(2 * aDay), recordAt(0)}, 3},
		{"a record with no timestamp gets no header",
			[]map[string]any{{"cmd": []any{"true"}}}, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, out := headersPrinted(t, tc.records)
			if got != tc.want {
				t.Errorf("printed %d date header(s), want %d:\n%s", got, tc.want, out)
			}
		})
	}
}

// Every record still prints a row, header or not: the grouping is decoration
// over the listing, and a repeated day must not swallow its records.
func TestRowPrintsEveryRecordWhateverTheDay(t *testing.T) {
	records := []map[string]any{recordAt(0), recordAt(0), recordAt(2 * aDay)}
	_, out := headersPrinted(t, records)
	if got := strings.Count(out, "true"); got != len(records) {
		t.Errorf("%d rows carry the command, want %d:\n%s", got, len(records), out)
	}
}

// A command blocked on its own escalation sits inside sudo for the whole wait,
// so the wall clock reports the operator's thinking time as the command's. The
// listing column is the run time; the detail view is where the wait and the
// wall clock are.
func TestTheListingShowsTheRunTimeNotTheWallClock(t *testing.T) {
	record := map[string]any{
		"op": "run", "exit_code": 1.0, "duration_sec": 50.52, "waited_sec": 50.51,
	}
	label, bad := outcome(record)
	if !strings.Contains(label, "0.01s") {
		t.Errorf("label = %q, want the run time rather than 50.52s", label)
	}
	if !bad {
		t.Error("a non-zero exit is still the row that asked to be read")
	}
	// And a record with no wait is unchanged: the two numbers are the same one.
	plain, _ := outcome(map[string]any{
		"op": "run", "exit_code": 0.0, "duration_sec": 12.44,
	})
	if !strings.Contains(plain, "12.44s") {
		t.Errorf("label = %q, want the duration untouched where nothing waited", plain)
	}
}
