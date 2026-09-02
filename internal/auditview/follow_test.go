package auditview

// The follower a watch reads through.

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
)

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
func drained(t *testing.T, f *Follower) []string {
	t.Helper()
	var ids []string
	if err := f.Drain(func(line []byte) {
		record, _ := ParseLine(line)
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	backlog := NewRing(1)
	if err := f.Drain(backlog.Add); err != nil {
		t.Fatal(err)
	}
	records, _ := ParseLines(backlog.Ordered())
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	drained(t, f)

	appendLog(t, path, `{"log_id":"last-before-rotation","op":"run"}`)
	if err := os.Rename(path, path+".1"); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"last-before-rotation"}) {
		t.Errorf("the rotated file's last records came out as %v, want them before the switch", ids)
	}
	rotated, err := f.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Error("a path with no file at it was read as a rotation: that is the gap " +
			"between the rename and the next record, and the file being read is still the log")
	}

	appendLog(t, path, `{"log_id":"first-after-rotation","op":"run"}`)
	rotated, err = f.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("a new file at the path was not read as a rotation")
	}
	if err := f.Reopen(); err != nil {
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	drained(t, f)

	if err := os.Truncate(path, 0); err != nil {
		t.Fatal(err)
	}
	rotated, err := f.Rotated()
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatalf("openFollower on a path with no log = %v, want a detached follower", err)
	}
	defer f.Close()
	if f.Following() {
		t.Error("a follower with no file at its path reports it is following one")
	}
	if ids := drained(t, f); ids != nil {
		t.Errorf("a detached follower yielded %v", ids)
	}
	rotated, err := f.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	if rotated {
		t.Error("a path that still has no file read as a rotation")
	}

	appendLog(t, path, `{"log_id":"first","op":"run"}`)
	rotated, err = f.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("the log appearing was not noticed, so nothing would ever attach to it")
	}
	if err := f.Reopen(); err != nil {
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
	f, err := OpenFollower(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	drained(t, f)

	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := f.Reopen(); !os.IsNotExist(err) {
		t.Fatalf("reopen with no file at the path = %v, want a not-exist error", err)
	}
	if ids := drained(t, f); ids != nil {
		t.Errorf("a pass after the failed reopen yielded %v", ids)
	}

	appendLog(t, path, `{"log_id":"b","op":"run"}`)
	rotated, err := f.Rotated()
	if err != nil {
		t.Fatal(err)
	}
	if !rotated {
		t.Fatal("the log coming back was not noticed")
	}
	if err := f.Reopen(); err != nil {
		t.Fatal(err)
	}
	if ids := drained(t, f); !slices.Equal(ids, []string{"b"}) {
		t.Errorf("after the log came back the watcher read %v, want it to carry on", ids)
	}
}
