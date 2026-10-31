package broker

import (
	"os"
	osexec "os/exec"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/redact"
)

func TestAuditStartFailureDoesNotExecute(t *testing.T) {
	if os.Getenv("FARAMIR_TEST_AUDIT_START") != "1" {
		executable, err := os.Executable()
		if err != nil {
			t.Fatal(err)
		}
		cmd := osexec.CommandContext(t.Context(), executable, "-test.run=^TestAuditStartFailureDoesNotExecute$")
		cmd.Env = append(os.Environ(), "FARAMIR_TEST_AUDIT_START=1")
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("audit start check: %v\n%s", err, out)
		}
		return
	}
	s, rec := execServer(t)
	// Opening and free-space checks succeed, but an actual append cannot.
	if reason := s.Audit.Unwritable(); reason != "" {
		t.Fatal(reason)
	}
	var limit unix.Rlimit
	if err := unix.Getrlimit(unix.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	limit.Cur = 0
	if err := unix.Setrlimit(unix.RLIMIT_FSIZE, &limit); err != nil {
		t.Fatal(err)
	}
	response := exec(t, s, map[string]any{"cmd": []any{"true"}})
	if code := errorCode(t, response); code != "no_audit" {
		t.Fatalf("error code %q, want no_audit", code)
	}
	if !strings.Contains(errorMessage(t, response), "command not run") {
		t.Fatal("missing execution refusal")
	}
	rec.none(t)
}

func TestAuditCompletionFailurePreservesCommandOutcome(t *testing.T) {
	for _, exitCode := range []int{0, 7} {
		s := newServer(t, map[string]string{"a/b": goodValue})
		s.exec = func(r *redact.Redactor, sink func(string), req execclient.Request) (*execclient.Result, error) {
			if req.Env["PW"] != goodValue {
				t.Fatal("requested credential was not injected")
			}
			if err := os.Rename(s.Config.Audit.LogPath, s.Config.Audit.LogPath+".started"); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(s.Config.Audit.LogPath, 0o700); err != nil {
				t.Fatal(err)
			}
			out := r.RedactText("result: " + req.Env["PW"])
			sink(out)
			return &execclient.Result{ExitCode: exitCode, Output: out, Truncated: true, TimedOut: true}, nil
		}
		response := exec(t, s, map[string]any{"cmd": []any{"true"},
			"env_refs": map[string]any{"PW": "faramir://a/b"}})
		if errorCode(t, response) != "audit_failed" || response["exit_code"] != exitCode {
			t.Fatalf("outcome not preserved: %v", response)
		}
		if output(t, response) != "result: «SECRET:a/b»" || response["truncated"] != true || response["timed_out"] != true {
			t.Fatalf("output conditions not preserved: %v", response)
		}
		if !strings.Contains(errorMessage(t, response), "command ran") ||
			!strings.Contains(errorMessage(t, response), "before retrying") {
			t.Fatal("audit failure does not explain execution and retry risk")
		}
	}
}

func TestRunUsesCapturedValuesAfterRefresh(t *testing.T) {
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": goodValue}, file)
	s := serverWith(t, k, file)
	s.exec = func(r *redact.Redactor, sink func(string), req execclient.Request) (*execclient.Result, error) {
		k.SetValues(map[string]string{"a/b": "replacement-test-credential"})
		s.Store.Reload()
		out := r.RedactText(req.Env["PW"])
		sink(out)
		return &execclient.Result{ExitCode: 0, Output: out}, nil
	}
	response := exec(t, s, map[string]any{"cmd": []any{"true", goodValue},
		"env_refs": map[string]any{"PW": "faramir://a/b"}})
	if response["error"] != nil || output(t, response) != "«SECRET:a/b»" {
		t.Fatalf("captured value was not redacted: %v", response)
	}
	entries := records(t, s)
	if len(entries) != 2 {
		t.Fatalf("got %d audit records, want 2", len(entries))
	}
	for _, entry := range entries {
		cmd, ok := entry["cmd"].([]any)
		if !ok || len(cmd) != 2 || cmd[1] != "«SECRET:a/b»" {
			t.Fatalf("audit metadata used a different value set: %v", entry)
		}
	}
}

func TestRunRefusalUsesCapturedValues(t *testing.T) {
	file := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": goodValue}, file)
	s := serverWith(t, k, file)
	secrets := s.Store.Snapshot()
	k.SetValues(map[string]string{"a/b": "replacement-test-credential"})
	s.Store.Reload()
	response := s.refuse(secrets, "bad_request", goodValue, "test-refusal", nil,
		[]string{"true", goodValue}, "/tmp/"+goodValue)
	if errorMessage(t, response) != "«SECRET:a/b»" {
		t.Fatal("refusal did not redact the captured value")
	}
	entries := records(t, s)
	if len(entries) != 1 {
		t.Fatalf("got %d refusal records, want 1", len(entries))
	}
	entry := entries[0]
	cmd, ok := entry["cmd"].([]any)
	if !ok || len(cmd) != 2 || cmd[1] != "«SECRET:a/b»" ||
		entry["cwd"] != "/tmp/«SECRET:a/b»" || entry["error"] != "«SECRET:a/b»" {
		t.Fatalf("refusal record used a different value set: %v", entry)
	}
}
