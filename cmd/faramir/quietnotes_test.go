package main

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/socktest"
	"github.com/andornaut/faramir/internal/testio"
)

// --quiet is how an agent runs a command, so what it suppresses decides what an
// agent can be told. The redaction count is a summary of a command that ran as
// asked; every other note says the output is not what the command produced, and
// a caller reading a truncated answer as the whole one is reading something
// else.
func TestQuietSuppressesTheSummaryAndNothingThatChangesTheOutput(t *testing.T) {
	response := map[string]any{
		"output":         "partial",
		"exit_code":      0,
		"truncated":      true,
		"invalid_bytes":  3,
		"timed_out":      true,
		"status_unknown": true,
		"log_id":         "ld000",
		"redactions":     []any{map[string]any{"token": "«SECRET:a/b»", "count": 2}},
	}
	for _, tc := range []struct {
		name  string
		quiet bool
		want  []string
		gone  []string
	}{
		{
			name: "the whole trailer is printed without --quiet",
			want: []string{"redacted «SECRET:a/b»×2", "output truncated",
				"3 non-text byte(s) replaced", "timed out",
				"exit status unknown", "log_id=ld000"},
		},
		{
			name:  "--quiet keeps every note that changes what the output means",
			quiet: true,
			want: []string{"output truncated", "3 non-text byte(s) replaced",
				"timed out", "exit status unknown"},
			gone: []string{"redacted", "log_id"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			socketPath := socktest.AnsweringBroker(t, response)
			said, _ := testio.CaptureStderr(t, func() int {
				return send("run", socketPath, map[string]any{"op": "run"}, false, tc.quiet)
			})
			for _, want := range tc.want {
				if !strings.Contains(said, want) {
					t.Errorf("stderr = %q, missing %q", said, want)
				}
			}
			for _, gone := range tc.gone {
				if strings.Contains(said, gone) {
					t.Errorf("stderr = %q, --quiet should have suppressed %q", said, gone)
				}
			}
		})
	}
}
