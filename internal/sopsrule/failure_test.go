package sopsrule

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// exitError is a real *exec.ExitError, which is what Failed is given by a sops
// that ran and failed.
func exitError(t *testing.T) error {
	t.Helper()
	err := exec.Command("sh", "-c", "exit 2").Run()
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Fatalf("sh did not exit non-zero: %v", err)
	}
	return err
}

// sops's header line and the exit status say nothing the detail does not, so
// the detail is what is kept, indented under the line that names the cause.
func TestFailedFoldsTheReasonUnderOneLine(t *testing.T) {
	stderr := "Error unmarshalling file: yaml: unmarshal errors:\n" +
		"  line 30: mapping key \"cloudflare_api_token\" already defined at line 9\n"
	got := Failed([]byte(stderr), exitError(t)).Error()
	want := "sops refused it:\n  line 30: mapping key \"cloudflare_api_token\" already defined at line 9"
	if got != want {
		t.Errorf("Failed =\n%s\nwant\n%s", got, want)
	}
}

// A failed decrypt closes with a paragraph about key groups in general, which
// is dropped; the per-key lines keep their nesting.
func TestFailedDropsTheRecoveryParagraph(t *testing.T) {
	stderr := "Failed to get the data key required to decrypt the SOPS file.\n\n" +
		"Group 0: FAILED\n" +
		"  age1example: FAILED\n" +
		"    - | no identity matched any of the recipients\n\n" +
		"Recovery failed because no master key was able to decrypt the file. In\n" +
		"order for SOPS to recover the file, at least one key has to be\n" +
		"successful, but none were.\n"
	got := Failed([]byte(stderr), exitError(t)).Error()
	want := "sops refused it:\n" +
		"  Failed to get the data key required to decrypt the SOPS file.\n" +
		"  Group 0: FAILED\n" +
		"    age1example: FAILED\n" +
		"      - | no identity matched any of the recipients"
	if got != want {
		t.Errorf("Failed =\n%s\nwant\n%s", got, want)
	}
	if line := FailedLine([]byte(stderr), exitError(t)).Error(); line !=
		"sops refused it: Failed to get the data key required to decrypt the SOPS file." {
		t.Errorf("FailedLine = %q", line)
	}
}

// A sops that printed nothing still says something: its exit status, that
// being all there is.
func TestFailedWithNoStderrNamesTheStatus(t *testing.T) {
	err := Failed(nil, exitError(t))
	if !strings.Contains(err.Error(), "exit status 2") || !strings.Contains(err.Error(), "no reason") {
		t.Errorf("Failed = %q, want the exit status and that sops gave no reason", err)
	}
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Error("the exit error is no longer reachable through Unwrap")
	}
}

// What sops prints reaches a terminal, so a control byte in it is escaped, and
// a run that prints without end is bounded both in bytes and in lines.
func TestCauseIsEscapedAndBounded(t *testing.T) {
	lines := Cause([]byte("bad \x1b[2J name\n"))
	if len(lines) != 1 || strings.Contains(lines[0], "\x1b") {
		t.Errorf("Cause = %q, want the escape made visible", lines)
	}
	lines = Cause([]byte(strings.Repeat("noise\n", 100)))
	if len(lines) != causeLines+1 || !strings.Contains(lines[causeLines], "more lines") {
		t.Errorf("Cause kept %d lines, want %d and a count of the rest", len(lines), causeLines+1)
	}

	var s Stderr
	n, err := s.Write(make([]byte, stderrCap+100))
	if n != stderrCap+100 || err != nil {
		t.Errorf("Write = %d, %v; a short write would end the copy from the child", n, err)
	}
	if len(s.Bytes()) != stderrCap {
		t.Errorf("kept %d bytes, want %d", len(s.Bytes()), stderrCap)
	}
}
