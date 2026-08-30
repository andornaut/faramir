package protocol

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/version"
)

// runWith is a run request carrying one extra field, which is what each case
// here varies.
func runWith(key string, value any) map[string]any {
	payload := map[string]any{
		"op": OpRun, "version": version.Version,
		"cmd": []any{"cat"}, "cwd": "/tmp",
	}
	if key != "" {
		payload[key] = value
	}
	return payload
}

// What a caller pipes in travels inside the request, base64, and is bounded
// there: the line the broker reads is bounded too, so an input larger than the
// cap has nowhere to go. Refused rather than truncated, a command that read the
// first half of its input having done something nobody asked for.
func TestWhatIsPipedInIsBoundedRatherThanCut(t *testing.T) {
	within := strings.Repeat("x", config.MaxStdinBytes)
	req, err := Parse(runWith("stdin", base64.StdEncoding.EncodeToString([]byte(within))))
	if err != nil {
		t.Fatalf("an input at the cap was refused: %v", err)
	}
	if len(req.Stdin) != len(within) {
		t.Errorf("stdin arrived as %d bytes, want %d", len(req.Stdin), len(within))
	}

	over := strings.Repeat("x", config.MaxStdinBytes+1)
	_, err = Parse(runWith("stdin", base64.StdEncoding.EncodeToString([]byte(over))))
	if err == nil {
		t.Fatal("an input past the cap was accepted, so it would be cut somewhere " +
			"nothing reports")
	}
	if !strings.Contains(err.Error(), "limit") {
		t.Errorf("the refusal does not say what the limit is: %v", err)
	}
}

// The two shapes that are not an input at all.
func TestStdinIsBase64AndOnlyARunTakesIt(t *testing.T) {
	if _, err := Parse(runWith("stdin", "not base64 at all!")); err == nil {
		t.Error("a value that is not base64 was accepted as an input")
	}
	if _, err := Parse(runWith("stdin", 7)); err == nil {
		t.Error("a number was accepted as an input")
	}
	// Every other op runs no child, so an input handed to one names something
	// that will never read it.
	redact := map[string]any{
		"op": "redact", "version": version.Version, "text": "x",
		"stdin": base64.StdEncoding.EncodeToString([]byte("x")),
	}
	if _, err := Parse(redact); err == nil {
		t.Error("an op that runs no child accepted an input for one")
	}
	// And a run with none is what every caller sends today.
	req, err := Parse(runWith("", nil))
	if err != nil {
		t.Fatalf("a run carrying no input was refused: %v", err)
	}
	if req.Stdin != nil {
		t.Errorf("a run carrying no input arrived with %d bytes", len(req.Stdin))
	}
}
