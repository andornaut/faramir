package main

import (
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/socktest"
	"github.com/andornaut/faramir/internal/testio"
)

func TestSendAuditFailurePreservesExecutedCommand(t *testing.T) {
	const message = "command ran but audit recording failed; verify before retry"
	for _, childCode := range []int{0, 7} {
		for _, mode := range []struct {
			name   string
			asJSON bool
			quiet  bool
		}{
			{name: "plain"},
			{name: "quiet", quiet: true},
			{name: "json", asJSON: true},
			{name: "quiet json", asJSON: true, quiet: true},
		} {
			t.Run(fmt.Sprintf("%s/exit%d", mode.name, childCode), func(t *testing.T) {
				response := map[string]any{
					"exit_code": childCode, "output": "preserved output\n", "log_id": "audit-test",
					"truncated": true, "timed_out": true, "status_unknown": true,
					"invalid_bytes": 2,
					"redactions":    []any{map[string]any{"token": "redacted-token", "count": 3}},
					"error":         map[string]any{"code": "audit_failed", "message": message},
				}
				socketPath := socktest.AnsweringBroker(t, response)
				var stderr string
				stdout, code := testio.CaptureStdout(t, func() int {
					var result int
					stderr, result = testio.CaptureStderr(t, func() int {
						return send("run", socketPath, map[string]any{"op": "run"}, mode.asJSON, mode.quiet)
					})
					return result
				})
				if code != 1 {
					t.Errorf("CLI exit = %d, want broker failure 1 despite child exit %d", code, childCode)
				}
				if mode.asJSON {
					var got, want map[string]any
					if err := json.Unmarshal([]byte(stdout), &got); err != nil {
						t.Fatalf("JSON output: %v: %q", err, stdout)
					}
					encoded, err := json.Marshal(response)
					if err != nil {
						t.Fatal(err)
					}
					if err := json.Unmarshal(encoded, &want); err != nil {
						t.Fatal(err)
					}
					if !reflect.DeepEqual(got, want) {
						t.Errorf("JSON response changed: got %v, want %v", got, want)
					}
					if stderr != "" {
						t.Errorf("JSON stderr = %q, want empty", stderr)
					}
					return
				}
				if stdout != response["output"] {
					t.Errorf("stdout = %q, want preserved output %q", stdout, response["output"])
				}
				wantError := "faramir run: audit_failed: " + message + "\nfaramir run: log_id=audit-test\n"
				if stderr != wantError {
					t.Errorf("stderr = %q, want %q", stderr, wantError)
				}
			})
		}
	}
}

func TestSendOtherBrokerErrorsStillSuppressOutput(t *testing.T) {
	for _, quiet := range []bool{false, true} {
		t.Run(fmt.Sprintf("quiet=%t", quiet), func(t *testing.T) {
			socketPath := socktest.AnsweringBroker(t, map[string]any{
				"exit_code": 0, "output": "must not be printed", "log_id": "refusal-test",
				"error": map[string]any{"code": "busy", "message": "try later"},
			})
			var stderr string
			stdout, code := testio.CaptureStdout(t, func() int {
				var result int
				stderr, result = testio.CaptureStderr(t, func() int {
					return send("run", socketPath, map[string]any{"op": "run"}, false, quiet)
				})
				return result
			})
			if code != 75 || stdout != "" {
				t.Errorf("exit = %d, stdout = %q, want 75 and no output", code, stdout)
			}
			for _, want := range []string{"busy: try later", "log_id=refusal-test"} {
				if !strings.Contains(stderr, want) {
					t.Errorf("stderr = %q, want %q", stderr, want)
				}
			}
		})
	}
}
