// Package runcmd runs a program and hands back what it printed.
//
// Three forms, because the callers differ in what they must not lose. Output
// keeps stdout alone: the broker prints its --check report there and logs on
// stderr, so a combined capture would make every report unparseable. Combined
// keeps both, for the programs whose answer is on stderr. OutputWithin adds a
// deadline, for a probe that must not hang the one command an operator runs
// when the host is already misbehaving.
//
// Every error names the program and its arguments, then what it wrote to
// stderr: a bare "exit status 1" says nothing an operator can act on, so the
// exit status is left out wherever the program said why.
package runcmd

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

// Output runs a program and returns its standard output. stdout alone: the
// broker prints its --check report there and logs on stderr, so a combined
// capture would make every report unparseable. stderr is carried in the
// error.
func Output(name string, args ...string) (string, error) {
	return OutputWithin(0, name, args...)
}

// OutputWithin is command under a deadline, for doctor's probes: a hung
// systemctl or broker hangs the one command an operator runs when the host is
// already misbehaving. Zero is no deadline, which is init's own paths: a step
// that takes long is a step to wait for, not one to abandon half-made.
func OutputWithin(within time.Duration, name string, args ...string) (string, error) {
	ctx := context.Background()
	if within > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, within)
		defer cancel()
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			err = fmt.Errorf("timed out after %s: %w", within, err)
		}
		return stdout.String(), failure(name, args, err, stderr.String())
	}
	return stdout.String(), nil
}

// Combined is Output for the programs whose answer is on stderr.
// systemd-analyze verify reports there and exits 0 either way.
func Combined(name string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), failure(name, args, err, string(out))
	}
	return string(out), nil
}

// failure is the error for a program that failed: the command line, then what
// it said. The exit status is dropped where the program said something and
// exited of its own accord; a signal, a timeout or a program that never
// started keeps its cause in front of whatever was printed. The cause is
// wrapped either way, so errors.As still reaches an *exec.ExitError.
func failure(name string, args []string, err error, said string) error {
	lines := meaningful(said)
	if !exitedOnItsOwn(err) || len(lines) == 0 {
		lines = append([]string{err.Error()}, lines...)
	}
	return &Error{Command: shortCommand(name, args), Lines: lines, Err: err}
}

// maxCommandRunes bounds the first line: a runuser wrapping a brokered probe
// runs to a few hundred characters, and the reason is the part worth reading.
const maxCommandRunes = 72

// shortCommand is the program's base name and its arguments, cut short past
// maxCommandRunes.
func shortCommand(name string, args []string) string {
	command := []rune(strings.TrimSpace(filepath.Base(name) + " " + strings.Join(args, " ")))
	if len(command) > maxCommandRunes {
		return string(command[:maxCommandRunes-1]) + "…"
	}
	return string(command)
}

// exitedOnItsOwn reports whether err is a program that ran and exited with a
// status, rather than one killed by a signal or one that never started.
func exitedOnItsOwn(err error) bool {
	exitErr, ok := errors.AsType[*exec.ExitError](err)
	if !ok {
		return false
	}
	if status, ok := exitErr.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		return false
	}
	return true
}

// meaningful is the non-blank lines of what a program printed, with trailing
// whitespace trimmed and leading indentation kept.
func meaningful(said string) []string {
	var lines []string
	for line := range strings.SplitSeq(said, "\n") {
		if line = strings.TrimRight(line, " \t\r"); strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// Error is a program that failed: what it printed, each line indented under
// "command:", or "command: <exit status>" where it printed nothing.
type Error struct {
	Command string
	Lines   []string
	Err     error
}

func (e *Error) Error() string {
	if len(e.Lines) == 1 && e.Lines[0] == e.Err.Error() {
		return e.Command + ": " + e.Lines[0]
	}
	return e.Command + ":\n  " + strings.Join(e.Lines, "\n  ")
}

func (e *Error) Unwrap() error { return e.Err }
