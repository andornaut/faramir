package main

import (
	"errors"
	"os/exec"
	"testing"
)

// childExitCode maps a finished child's error to the status faramir exits with.
// The signal case is the one that regressed: `faramir redact -- CMD` returned
// 255 for a killed child where `faramir run` and every shell return 128+signal.
func TestChildExitCode(t *testing.T) {
	if got := childExitCode(nil); got != 0 {
		t.Errorf("a clean exit = %d, want 0", got)
	}

	// A real child, so the ExitError carries a real WaitStatus rather than a
	// hand-built one: this is exactly what redactChild sees from cmd.Wait.
	exit := func(t *testing.T, argv ...string) error {
		t.Helper()
		err := exec.Command(argv[0], argv[1:]...).Run()
		if err == nil {
			t.Fatalf("%v exited 0, wanted a failure", argv)
		}
		return err
	}

	if got := childExitCode(exit(t, "sh", "-c", "exit 9")); got != 9 {
		t.Errorf("an exit status = %d, want 9", got)
	}
	// 128 + SIGKILL(9) and 128 + SIGTERM(15).
	if got := childExitCode(exit(t, "sh", "-c", "kill -KILL $$")); got != 137 {
		t.Errorf("a SIGKILL death = %d, want 137 (128+9), not the -1 that renders as 255", got)
	}
	if got := childExitCode(exit(t, "sh", "-c", "kill -TERM $$")); got != 143 {
		t.Errorf("a SIGTERM death = %d, want 143 (128+15)", got)
	}

	// An error that is not a child exit at all: the caller reports it and treats
	// it as its own failure, which -1 signals.
	if got := childExitCode(errors.New("dial failed")); got != -1 {
		t.Errorf("a non-exit error = %d, want -1", got)
	}
}
