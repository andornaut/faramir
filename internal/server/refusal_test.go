package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/sockutil"
)

// records returns every audit record written so far.
func records(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	body, err := os.ReadFile(s.Config.Audit.LogPath)
	if err != nil {
		return nil
	}
	var out []map[string]any
	for line := range strings.SplitSeq(strings.TrimSpace(string(body)), "\n") {
		if line == "" {
			continue
		}
		var record map[string]any
		if json.Unmarshal([]byte(line), &record) == nil {
			out = append(out, record)
		}
	}
	return out
}

// A refusal hands the caller a log_id, and `faramir mcp` passes it to the model
// as something the operator can look up.  An id naming no record sends somebody
// to look up nothing, and it is the same question the log answers for every
// other outcome: why did this not run.
func TestEveryRefusalWithALogIDIsRecorded(t *testing.T) {
	const value = "hunter2-correct-horse"
	peer := &sockutil.Peer{PID: 4242, UID: 1000, GID: 1000}

	for _, probe := range []struct {
		name    string
		code    string
		request map[string]any
	}{
		{"no cwd", "bad_request", map[string]any{
			"op": "exec", "cmd": []any{"/bin/true"}}},
		{"cwd does not exist", "bad_request", map[string]any{
			"op": "exec", "cmd": []any{"/bin/true"}, "cwd": "/nonexistent-dir"}},
		{"cwd is a file", "bad_request", map[string]any{
			"op": "exec", "cmd": []any{"/bin/true"}, "cwd": "/etc/hostname"}},
		{"a ref nothing holds", "unknown_secret", map[string]any{
			"op": "exec", "cmd": []any{"/bin/true"}, "cwd": "/tmp",
			"env_refs": map[string]any{"X": "secret://no/such/ref"}}},
	} {
		t.Run(probe.name, func(t *testing.T) {
			s := newServer(t, map[string]string{"db/password": value})
			response := s.Handle(probe.request, peer)

			failure, ok := response["error"].(map[string]string)
			if !ok {
				t.Fatalf("not refused: %v", response)
			}
			if failure["code"] != probe.code {
				t.Errorf("code %q, want %q", failure["code"], probe.code)
			}
			logID, _ := response["log_id"].(string)
			if logID == "" {
				t.Fatal("the refusal carried no log_id")
			}
			found := false
			for _, record := range records(t, s) {
				if record["log_id"] == logID {
					found = true
					if record["refused"] != probe.code {
						t.Errorf("record says refused=%v, want %q", record["refused"], probe.code)
					}
					if record["peer"] == nil {
						t.Error("the record does not name the peer that asked")
					}
				}
			}
			if !found {
				t.Errorf("log_id %s names no record: the caller was sent to look up "+
					"something that is not there", logID)
			}
		})
	}
}

// The other half of the rule: a refusal decided before the request is parsed
// carries no id, so there is nothing to look up and nothing that should have
// been recorded.
func TestARefusalDecidedBeforeParsingCarriesNoLogID(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	response := s.Handle(map[string]any{
		"op": "exec", "cmd": []any{"/bin/true"}, "cwd": "/tmp",
		"env_refs": map[string]any{"X": "not-a-uri"}},
		&sockutil.Peer{PID: 7, UID: 1000, GID: 1000})

	failure, ok := response["error"].(map[string]string)
	if !ok || failure["code"] != "bad_request" {
		t.Fatalf("want a parse refusal, got %v", response)
	}
	if id := response["log_id"]; id != nil {
		t.Errorf("log_id = %v, want none: nothing was recorded to look up", id)
	}
}

// The concurrency refusal is the one an operator is likeliest to chase, every
// slot being held by something they cannot see from the caller's side.
func TestABusyRefusalIsRecorded(t *testing.T) {
	s := newServer(t, map[string]string{"db/password": "hunter2-correct-horse"})
	s.Config.Command.Concurrency = 1
	s.slots = make(chan struct{}, 1)
	s.slots <- struct{}{} // the one slot, taken

	response := s.Handle(map[string]any{
		"op": "exec", "cmd": []any{"/bin/true"}, "cwd": "/tmp"},
		&sockutil.Peer{PID: 7, UID: 1000, GID: 1000})

	failure, ok := response["error"].(map[string]string)
	if !ok || failure["code"] != "busy" {
		t.Fatalf("want a busy refusal, got %v", response)
	}
	logID, _ := response["log_id"].(string)
	for _, record := range records(t, s) {
		if record["log_id"] == logID && record["refused"] == "busy" {
			return
		}
	}
	t.Errorf("the busy refusal (log_id %s) was not recorded", logID)
}

// A refusal is agent-visible text, so it goes through the redactor like every
// other one: an error that interpolated a value would otherwise put it both in
// the answer and on disk.
func TestARefusalCarriesNoValue(t *testing.T) {
	const value = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"db/password": value})
	// The cwd is echoed back in the message, so a value there is the way one
	// reaches the text at all.  Under a directory this test made, because a
	// path that merely looks absent may exist and be unreadable, which the
	// broker deliberately leaves to the executor rather than refusing.
	missing := filepath.Join(t.TempDir(), value)
	response := s.Handle(map[string]any{
		"op": "exec", "cmd": []any{"/bin/true"}, "cwd": missing},
		&sockutil.Peer{PID: 7, UID: 1000, GID: 1000})

	failure, _ := response["error"].(map[string]string)
	if strings.Contains(failure["message"], value) {
		t.Errorf("the refusal message carries the value: %q", failure["message"])
	}
	if !strings.Contains(failure["message"], "«SECRET:db/password»") {
		t.Errorf("the value was neither redacted nor present: %q", failure["message"])
	}
	body, _ := os.ReadFile(s.Config.Audit.LogPath)
	if strings.Contains(string(body), value) {
		t.Error("the audit record carries the value")
	}
}
