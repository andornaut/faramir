package auditview

// The field renderings the rows are built from.

import (
	"strings"
	"testing"
)

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
