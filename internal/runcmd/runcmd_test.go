package runcmd

// What a command returns and what its failure carries.

import (
	"encoding/json"
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
}
