package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/fserr"
)

// newRedactCmd scrubs text that did not come from a brokered command. As a
// filter it reads stdin; given a command after --, it runs that command and
// filters what it prints, preserving its exit status. One failure policy for
// both shapes: text that could not be redacted is never written, and the exit
// status is non-zero.
//
// It takes no --json. Every other broker op is one request and one response,
// which that flag prints; a redaction is a stream of them, and the output is
// the redacted text rather than a reply to render. A flag accepted here and
// read by nothing said this command had a raw response to show.
func newRedactCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "redact [options] [-- command [args...]]",
		Short:   "Remove secrets from text, or from a command's output",
		GroupID: groupAgent,
		RunE: func(c *cobra.Command, child []string) error {
			if len(child) > 0 {
				return codeErr(redactChild(socketDefault(), child))
			}
			if err := brokerclient.RedactStreamLive(socketDefault(), os.Stdin, os.Stdout); err != nil {
				fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
				return codeErr(1)
			}
			return nil
		},
	}
	return c
}

// redactChild runs the command with both its streams merged and filtered.
// Merged because the agent reads them as one transcript. stdin is passed
// through.
func redactChild(socketPath string, argv []string) int {
	cmd := exec.CommandContext(context.Background(), argv[0], argv[1:]...)
	cmd.Stdin = os.Stdin
	output, err := cmd.StdoutPipe()
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		return 1
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		// The path once and what the kernel said: exec.Error carries the name and
		// wraps it in "fork/exec", which is Go's plumbing rather than the reader's.
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", fserr.At(argv[0], err))
		// The shell's two conditions, which `faramir run` gives for the same:
		// 126 for a program that is there and cannot be run, 127 for one that is
		// not there. Distinct codes so a script does not read "not installed"
		// where the file is present and not executable.
		if errors.Is(err, os.ErrPermission) || errors.Is(err, syscall.ENOEXEC) {
			return 126
		}
		return 127
	}
	streamErr := brokerclient.RedactStream(socketPath, output, os.Stdout)
	if streamErr != nil {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", streamErr)
		// Drain, or a child that fills the pipe blocks the Wait below. Discarded
		// rather than written: this is the text that could not be redacted.
		_, _ = io.Copy(io.Discard, output)
	}
	err = cmd.Wait()

	code := brokerclient.ChildExitCode(err)
	if code < 0 {
		fmt.Fprintf(os.Stderr, "faramir redact: %v\n", err)
		code = 1
	}
	// The command still ran, and what is missing is the part of its output that
	// could not be redacted. Its own status is kept when it failed, and a success
	// becomes a failure: withheld output must not read as a command that printed
	// nothing. wrap.sh does the same.
	if streamErr != nil && code == 0 {
		code = 1
	}
	return code
}
