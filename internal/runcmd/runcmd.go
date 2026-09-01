// Package runcmd runs a program and hands back what it printed.
//
// Three forms, because the callers differ in what they must not lose. Output
// keeps stdout alone: the broker prints its --check report there and logs on
// stderr, so a combined capture would make every report unparseable. Combined
// keeps both, for the programs whose answer is on stderr. OutputWithin adds a
// deadline, for a probe that must not hang the one command an operator runs
// when the host is already misbehaving.
//
// Every error names the program, its arguments and what it wrote to stderr: a
// bare "exit status 1" says nothing an operator can act on.
package runcmd

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
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
		return stdout.String(), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.String(), nil
}

// Combined is Output for the programs whose answer is on stderr.
// systemd-analyze verify reports there and exits 0 either way.
func Combined(name string, args ...string) (string, error) {
	cmd := exec.CommandContext(context.Background(), name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %w: %s",
			name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}
