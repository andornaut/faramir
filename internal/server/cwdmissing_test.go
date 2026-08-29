package server

import (
	"strings"
	"testing"
)

// A working directory the caller can list and the broker cannot find. Every
// faramir unit runs with PrivateTmp=true, so the daemon's /tmp and /var/tmp are
// its own; "cwd does not exist" about a directory that plainly does
// reads as a broker fault rather than as the boundary it is, and scratch under
// /tmp is where anyone would put a working directory first.
func TestCwdMissingNamesPrivateTmpWhereThatIsTheReason(t *testing.T) {
	for _, tc := range []struct {
		name    string
		cwd     string
		private bool
	}{
		{"under /tmp", "/tmp/faramir-agent-test-work", true},
		{"under /var/tmp", "/var/tmp/build", true},
		// /dev/shm is NOT private: it is shared with the caller, which is what
		// makes a brokered command's leavings there the caller's to find. Blaming
		// PrivateTmp for it would steer the reader away from the one hierarchy
		// that is actually shared.
		{"under /dev/shm, which is shared", "/dev/shm/scratch", false},
		{"/tmp itself", "/tmp", true},
		// Not private, so the ordinary message is the true one: this directory is
		// absent for the daemon and for the caller alike.
		{"an ordinary path", "/srv/project/gone", false},
		// A prefix that is not a path component. "/tmpfoo" is not under "/tmp",
		// and blaming PrivateTmp for it would send the reader somewhere useless.
		{"a path that merely starts with the same letters", "/tmpfoo/x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := cwdMissing(tc.cwd)
			if !strings.Contains(got, tc.cwd) {
				t.Errorf("the message should name the directory: %q", got)
			}
			if blames := strings.Contains(got, "PrivateTmp"); blames != tc.private {
				t.Errorf("PrivateTmp named = %v, want %v: %q", blames, tc.private, got)
			}
		})
	}
}
