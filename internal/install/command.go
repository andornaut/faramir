package install

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// commandError is a program that failed, carrying what it said on stderr
// rather than the exit status alone. Its message is the cause and nothing
// else: the caller names the object.
type commandError struct {
	program string
	stderr  string
	err     error
}

func (e *commandError) Error() string {
	lines := causeLines(e.stderr)
	switch len(lines) {
	case 0:
		return fmt.Sprintf("%s: %v", e.program, e.err)
	case 1:
		return lines[0]
	}
	return "\n  " + strings.Join(lines, "\n  ")
}

func (e *commandError) Unwrap() error { return e.err }

// causeLines is a child's stderr without its blank lines.
func causeLines(stderr string) []string {
	var lines []string
	for line := range strings.Lines(stderr) {
		if line = strings.TrimSpace(line); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// command runs a program and returns its stdout. On failure the error is a
// commandError holding stderr.
func command(name string, args ...string) (string, error) {
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(context.Background(), name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		return stdout.String(), &commandError{program: name, stderr: stderr.String(), err: err}
	}
	return stdout.String(), nil
}

// failed names what did not happen and folds the cause under it: on the same
// line when it is one line, indented beneath when it is several.
func failed(what string, err error) error {
	msg := err.Error()
	if strings.HasPrefix(msg, "\n") {
		return fmt.Errorf("%s:%w", what, err)
	}
	return fmt.Errorf("%s: %w", what, err)
}
