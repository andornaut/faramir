package main

import (
	"bytes"
	"encoding/base64"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Both spellings, because both are typed: a bare number is what these flags
// have always taken, and a duration is what a caller writes without thinking
// about the unit. The refusals are asserted for what they name, a message that
// says only "invalid syntax" being the friction this replaced.
func TestADurationFlagTakesBothSpellings(t *testing.T) {
	for _, tc := range []struct {
		value string
		want  int
		says  string
	}{
		{value: "", want: 0},
		{value: "300", want: 300},
		{value: "0", want: 0},
		{value: "90s", want: 90},
		{value: "5m", want: 300},
		{value: "1h30m", want: 5400},
		{value: "1500ms", says: "whole seconds"},
		{value: "-5", says: "must not be negative"},
		{value: "-5m", says: "must not be negative"},
		{value: "nonsense", says: "takes a duration"},
		{value: "5 m", says: "takes a duration"},
	} {
		t.Run(tc.value, func(t *testing.T) {
			got, err := durationSeconds("--timeout", tc.value)
			if tc.says != "" {
				if err == nil {
					t.Fatalf("durationSeconds(%q) = %d, want a refusal naming %q",
						tc.value, got, tc.says)
				}
				if !strings.Contains(err.Error(), tc.says) {
					t.Errorf("refusal is %q, want it to name %q", err, tc.says)
				}
				if !strings.Contains(err.Error(), "--timeout") {
					t.Errorf("refusal is %q, and names no flag, so a caller reading it "+
						"does not know which one to retype", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("durationSeconds(%q): %v", tc.value, err)
			}
			if got != tc.want {
				t.Errorf("durationSeconds(%q) = %d, want %d", tc.value, got, tc.want)
			}
		})
	}
}

// A default is stored in seconds and printed beside a flag that takes a
// duration, which is where a caller learns the spelling.
func TestADefaultIsShownAsADuration(t *testing.T) {
	if got := asDuration(600); got != "10m0s" {
		t.Errorf("asDuration(600) = %q, want 10m0s", got)
	}
}

// The stdin cap leaves room for an ordinary command beside it, and a long
// command plus a maximal input still overruns the line the broker reads. The
// broker answers that with the size of the line, which names neither half, so
// the client says which it was while it still has both.
func TestARequestTooLargeToSendNamesWhichHalfIsBig(t *testing.T) {
	small := map[string]any{"op": "run", "cmd": []string{"true"}}
	if err := fitsOneRequest(small, 0); err != nil {
		t.Fatalf("an ordinary request was refused: %v", err)
	}
	// The command and the input together, as the client sends them: the input
	// is already base64 in the request, which is what has to fit.
	piped := bytes.Repeat([]byte("x"), 128<<10)
	big := map[string]any{
		"op": "run", "cmd": []string{strings.Repeat("a", 100000)},
		"stdin": base64.StdEncoding.EncodeToString(piped),
	}
	err := fitsOneRequest(big, len(piped))
	if err == nil {
		t.Fatal("a request past the line the broker reads was accepted")
	}
	for _, want := range []string{"bytes of input", "shorten the command"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal is %q, and does not say %q", err, want)
		}
	}
	// And with nothing piped in it does not blame an input that was never there.
	delete(big, "stdin")
	big["cmd"] = []string{strings.Repeat("a", 300000)}
	err = fitsOneRequest(big, 0)
	if err == nil {
		t.Fatal("a long command alone was accepted")
	}
	if strings.Contains(err.Error(), "input") {
		t.Errorf("the refusal blames an input the caller never gave: %v", err)
	}
}

// -i is what says the input is meant for the command. Without it a pipeline is
// refused rather than dropped, and every other stdin is left alone: a `while
// read` loop and an ssh session both hand this process a file they are still
// using, and reading either would take input away from its owner.
func TestAPipelineWithoutTheFlagIsRefusedAndNothingElseIsRead(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = reader.Close() }()
	// Written and closed: a reader waits for the end of a pipe, and a writer
	// left open is a test that hangs rather than one that fails.
	if _, err := writer.WriteString("x"); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	saved := os.Stdin
	os.Stdin = reader
	defer func() { os.Stdin = saved }()

	if _, err := pipedStdin(false); err == nil {
		t.Error("a pipeline with no -i was accepted, so the input reaches nothing " +
			"and nobody is told")
	}
	piped, err := pipedStdin(true)
	if err != nil {
		t.Fatalf("-i refused a pipeline: %v", err)
	}
	if string(piped) != "x" {
		t.Errorf("-i read %q, want the piped byte", piped)
	}

	// A regular file is one this process does not own: read here, the loop that
	// opened it gets nothing.
	path := filepath.Join(t.TempDir(), "hosts.txt")
	if err := os.WriteFile(path, []byte("a\nb\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	file, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	os.Stdin = file
	if _, err := pipedStdin(false); err != nil {
		t.Errorf("an inherited file was refused, and no pipeline was there to send: %v", err)
	}
	if at, err := file.Seek(0, io.SeekCurrent); err != nil || at != 0 {
		t.Errorf("the file was read to offset %d, so the caller that opened it lost that much", at)
	}
}
