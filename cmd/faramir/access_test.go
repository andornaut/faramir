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
		name        string
		path        string
		read, write bool
		want        int
	}{
		{"neither flag is not a question", readable, false, false, 2},
		{"a readable file", readable, true, false, 0},
		{"a writable file", readable, false, true, 0},
		{"both at once", readable, true, true, 0},
		{"a path that is not there", filepath.Join(dir, "absent"), true, false, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := runAccess(tc.path, tc.read, tc.write); got != tc.want {
				t.Errorf("runAccess(%q, read=%v, write=%v) = %d, want %d",
					tc.path, tc.read, tc.write, got, tc.want)
			}
		})
	}
}

// A mode that permits nothing answers no.  Skipped as root, for whom it answers
// yes and rightly: root's access is not what this reports on.
func TestAccessRefusesAModeThatPermitsNothing(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root's access(2) is not refused by a mode, so this says nothing as root")
	}
	closed := filepath.Join(t.TempDir(), "closed")
	if err := os.WriteFile(closed, []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if got := runAccess(closed, true, false); got != 1 {
		t.Errorf("runAccess on a 0000 file = %d, want 1", got)
	}
}
