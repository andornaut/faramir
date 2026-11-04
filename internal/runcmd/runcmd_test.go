package runcmd

// What a command returns and what its failure carries.

import (
	"encoding/json"
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// The broker prints its --check report on stdout and logs on stderr on every
// load, so a combined capture makes every report unparseable.
func TestCommandReturnsStdoutOnly(t *testing.T) {
	out, err := Output("sh", "-c", `echo "loaded 3 vault refs" >&2; echo '{"ok":true}'`)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "loaded 3 vault refs") {
		t.Fatalf("stderr leaked into stdout: %q", out)
	}
	var report struct {
		OK bool `json:"ok"`
	}
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("stdout did not parse on its own: %v", err)
	}
	if !report.OK {
		t.Error("wrong value parsed")
	}
}

// A failure has to carry stderr, which is where the reason is.
func TestCommandErrorCarriesStderr(t *testing.T) {
	_, err := Output("sh", "-c", `echo "the reason" >&2; exit 3`)
	if err == nil {
		t.Fatal("no error from a command that exited 3")
	}
	if !strings.Contains(err.Error(), "the reason") {
		t.Errorf("error does not carry stderr: %v", err)
	}
	// The reason stands in for the exit status, which says nothing beside it.
	if strings.Contains(err.Error(), "exit status") {
		t.Errorf("error carries the exit status as well as the reason: %v", err)
	}
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		t.Errorf("the exit is no longer reachable through the error: %v", err)
	}
}

// stderr goes on indented lines under the command, blank lines dropped, and a
// program that said nothing is reported by its exit status.
func TestCommandErrorShape(t *testing.T) {
	_, err := Output("/bin/sh", "-c", `printf 'first\n\n  second\n' >&2; exit 2`)
	if want := "sh -c printf 'first\\n\\n  second\\n' >&2; exit 2:\n  first\n    second"; err == nil || err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	_, err = Output("sh", "-c", "echo one line >&2; exit 2")
	if want := "sh -c echo one line >&2; exit 2:\n  one line"; err == nil || err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	_, err = Output("sh", "-c", "exit 4")
	if want := "sh -c exit 4: exit status 4"; err == nil || err.Error() != want {
		t.Errorf("err = %q, want %q", err, want)
	}
	// A long command line is cut, so the reason is not buried under it.
	_, err = Output("sh", "-c", "exit 4", strings.Repeat("x", 200))
	if first, _, _ := strings.Cut(err.Error(), ":"); len([]rune(first)) > maxCommandRunes {
		t.Errorf("first line runs to %d characters: %q", len([]rune(first)), first)
	}
}
