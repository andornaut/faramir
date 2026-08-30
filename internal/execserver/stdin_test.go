package execserver

import (
	"strings"
	"testing"
	"time"
)

// What the caller piped in reaches the child, and the child sees the end of it.
// Before this the executor gave every child /dev/null, so a pipeline into a
// brokered command wrote an empty file and reported success.
func TestWhatWasPipedInReachesTheChild(t *testing.T) {
	_, sock, dir := newExecutor(t)

	result, output, err := runChildWithStdin(t, sock,
		[]string{"/bin/cat"}, dir, []byte("PIPED-IN\n"))
	if err != nil {
		t.Fatalf("the executor refused the command: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit = %d, output = %q", result.ExitCode, output)
	}
	if !strings.Contains(output, "PIPED-IN") {
		t.Errorf("the child read %q, and nothing of what was piped in", output)
	}
}

// And a child given nothing still reaches EOF rather than waiting out its
// timeout: that is what /dev/null was there for, and it is still what an empty
// stdin gets.
func TestAChildGivenNothingStillSeesTheEnd(t *testing.T) {
	_, sock, dir := newExecutor(t)

	started := time.Now()
	result, output, err := runChildWithStdin(t, sock, []string{"/bin/cat"}, dir, nil)
	if err != nil {
		t.Fatalf("the executor refused the command: %v", err)
	}
	if result.ExitCode != 0 {
		t.Fatalf("exit = %d, output = %q", result.ExitCode, output)
	}
	// Well inside the five seconds the run was given, which is what says the
	// child read an EOF rather than being killed at its timeout.
	if waited := time.Since(started); waited > 4*time.Second {
		t.Errorf("a child with nothing to read took %s, so it waited for input "+
			"that was never coming", waited)
	}
}
