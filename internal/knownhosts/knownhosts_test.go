package knownhosts

// Counting and reading a known_hosts file.

import (
	"os"
	"path/filepath"
	"testing"
)

// ssh reads a known_hosts file line by line and ignores what it cannot parse, so
// counting what it would take means counting past a bad line rather than
// rejecting the file: one hand edit in a file of two hundred must not be
// reported as a host that verifies nothing.
func TestCountKnownHostsCountsPastALineItCannotParse(t *testing.T) {
	const key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleExampleExampleExample"
	dir := t.TempDir()
	mixed := filepath.Join(dir, "mixed")
	body := "one.example.com " + key + "\ntruncated.example.com ssh-ed\ntwo.example.com " + key + "\n"
	if err := os.WriteFile(mixed, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}

	if got := Count(mixed); got != 2 {
		t.Errorf("Count = %d, want 2: the entries either side of a bad line "+
			"still verify their hosts", got)
	}
	// The strict read is a different question, asked of a path the operator named
	// before it is copied, and it still refuses the same file.
	if _, _, err := Read(mixed); err == nil {
		t.Error("--known-hosts accepted a file with a line it could not parse")
	}
	if got := Count(filepath.Join(dir, "absent")); got != 0 {
		t.Errorf("Count(absent) = %d, want 0", got)
	}
}
