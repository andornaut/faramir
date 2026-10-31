package main

import (
	"bufio"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/termui"
	"github.com/andornaut/faramir/internal/testio"
)

func TestJSONReportsStdoutFailure(t *testing.T) {
	output, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	saved := os.Stdout
	os.Stdout = output
	t.Cleanup(func() {
		os.Stdout = saved
		_ = output.Close()
	})
	said, code := testio.CaptureStderr(t, func() int {
		return printJSON("status", map[string]string{"state": "ready"})
	})
	if code != 1 || !strings.Contains(said, "faramir status: writing output:") {
		t.Fatalf("stdout failure returned %d, stderr %q", code, said)
	}
}

func TestJSONWatchReportsStdoutFailure(t *testing.T) {
	if mode := os.Getenv("FARAMIR_TEST_JSON_WATCH"); mode != "" {
		count := 1
		if mode == "live" {
			count = 0
		}
		os.Exit(runWatch(os.Getenv("FARAMIR_TEST_JSON_WATCH_PATH"),
			logsFlags{asJSON: true, count: count}, termui.Palette{}))
	}
	for _, mode := range []string{"backlog", "live"} {
		t.Run(mode, func(t *testing.T) {
			const record = "{\"op\":\"run\",\"log_id\":\"test\",\"exit_code\":0}\n"
			path := filepath.Join(t.TempDir(), "events.jsonl")
			initial := ""
			if mode == "backlog" {
				initial = record
			}
			if err := os.WriteFile(path, []byte(initial), 0o600); err != nil {
				t.Fatal(err)
			}
			output, err := os.Open(os.DevNull)
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = output.Close() }()
			ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
			defer cancel()
			executable, err := os.Executable()
			if err != nil {
				t.Fatal(err)
			}
			cmd := exec.CommandContext(ctx, executable, "-test.run=^TestJSONWatchReportsStdoutFailure$")
			cmd.Env = append(os.Environ(), "FARAMIR_TEST_JSON_WATCH="+mode, "FARAMIR_TEST_JSON_WATCH_PATH="+path)
			cmd.Stdout = output
			stderr, err := cmd.StderrPipe()
			if err != nil {
				t.Fatal(err)
			}
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			var said strings.Builder
			scanner := bufio.NewScanner(stderr)
			for scanner.Scan() {
				line := scanner.Text()
				said.WriteString(line + "\n")
				if mode == "live" && strings.HasPrefix(line, "watching ") {
					if err := os.WriteFile(path, []byte(record), 0o600); err != nil {
						t.Error(err)
						cancel()
					}
				}
			}
			if err := scanner.Err(); err != nil {
				t.Error(err)
			}
			err = cmd.Wait()
			var exit *exec.ExitError
			if ctx.Err() != nil || !errors.As(err, &exit) || exit.ExitCode() != 1 {
				t.Fatalf("watch did not exit on output failure: %v; %s", err, said.String())
			}
			if !strings.Contains(said.String(), "faramir logs: writing output:") {
				t.Fatalf("watch did not report the output failure: %s", said.String())
			}
		})
	}
}
