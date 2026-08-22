package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The exit status is the whole interface: doctor reads nothing else, so a path
// that answers 0 without having been asked a question is a boundary reported as
// open on the strength of an empty command line.
func TestAccessAnswersOnlyWhatItWasAsked(t *testing.T) {
	dir := t.TempDir()
	readable := filepath.Join(dir, "readable")
	if err := os.WriteFile(readable, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name                 string
		path                 string
		read, write, execute bool
		want                 int
	}{
		{"no flag is not a question", readable, false, false, false, 2},
		{"a readable file", readable, true, false, false, 0},
		{"a writable file", readable, false, true, false, 0},
		{"both at once", readable, true, true, false, 0},
		{"a traversable directory", dir, false, false, true, 0},
		{"read and traverse together", dir, true, false, true, 0},
		{"a path that is not there", filepath.Join(dir, "absent"), true, false, false, 1},
		{"traversing what is not there", filepath.Join(dir, "absent"), false, false, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := runAccess(tc.path, tc.read, tc.write, tc.execute)
			if got != tc.want {
				t.Errorf("runAccess(%q, read=%v, write=%v, execute=%v) = %d, want %d",
					tc.path, tc.read, tc.write, tc.execute, got, tc.want)
			}
		})
	}
}

// The bit the traversal question exists to read. A directory that is readable
// and not executable lists its names and passes nobody through, so an answer
// worked out from the read would report reachable what is not: that is the
// false pass diagnoseOperatorKeys carried, claiming traversal it never asked
// about. Skipped as root, whose access(2) a mode does not refuse.
func TestAccessSeparatesTraversalFromReading(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root traverses a directory whatever its mode, so this says nothing as root")
	}
	listable := filepath.Join(t.TempDir(), "listable")
	if err := os.Mkdir(listable, 0o400); err != nil {
		t.Fatal(err)
	}
	if got := runAccess(listable, true, false, false); got != 0 {
		t.Errorf("reading a 0400 directory = %d, want 0", got)
	}
	if got := runAccess(listable, false, false, true); got != 1 {
		t.Errorf("traversing a 0400 directory = %d, want 1", got)
	}
}

// A mode that permits nothing answers no. Skipped as root, for whom it answers
// yes and rightly: root's access is not what this reports on.
func TestAccessRefusesAModeThatPermitsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's access(2) is not refused by a mode, so this says nothing as root")
	}
	closed := filepath.Join(t.TempDir(), "closed")
	if err := os.WriteFile(closed, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if got := runAccess(closed, true, false, false); got != 1 {
		t.Errorf("runAccess on a 0000 file = %d, want 1", got)
	}
}
