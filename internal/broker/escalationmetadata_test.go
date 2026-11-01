package broker

import (
	"os"
	"path/filepath"
	"slices"
	"testing"
	"testing/synctest"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
)

func TestEscalationQuestionsAndAuditRedactCommandMetadata(t *testing.T) {
	synctest.Test(t, func(t *testing.T) {
		const marker = "synthetic-metadata-value"
		const token = "«SECRET:fixture/value»"
		original := escalation.Run{
			Argv: []string{"bin/tool", marker}, Cwd: "/work/" + marker,
			Argv0Path: "/work/" + marker + "/bin/tool", LogID: "metadata-test",
		}
		captured := redact.NewValues([]redact.Secret{{Ref: "fixture/value", Value: marker}}, redact.DefaultPolicy())
		metadata := escalationMetadata(captured.Redactor(), original)
		s := escalation.New(config.SudoConfig{ExecUser: "test-executor", TimeoutSec: 10})
		t.Cleanup(s.Stop)
		runID, heldBy := s.Register(metadata)
		if runID == "" || heldBy != "" {
			t.Fatalf("register: runID=%q heldBy=%q", runID, heldBy)
		}
		s.Owner = func([]int) (string, string) { return runID, "test executor" }
		s.Quiescent = func() (bool, string) { return true, "test executor" }
		entries := make(chan map[string]any, 1)
		s.Record = func(entry map[string]any) { entries <- entry }
		approved := make(chan bool, 1)
		go func() {
			yes, _, _ := s.Ask([]int{42})
			approved <- yes
		}()
		synctest.Wait()
		questions := s.Questions()
		if len(questions) != 1 {
			t.Fatalf("got %d questions, want 1", len(questions))
		}
		question := questions[0]
		if question.Cmd != "bin/tool "+token || question.Cwd != "/work/"+token ||
			question.Program != "/work/"+token+"/bin/tool" {
			t.Errorf("question metadata: cmd=%q cwd=%q program=%q", question.Cmd, question.Cwd, question.Program)
		}
		if err := s.Answer(question.ID, true, "test operator"); err != nil {
			t.Fatal(err)
		}
		if !<-approved {
			t.Fatal("the request was refused")
		}
		entry := <-entries
		argv, ok := entry["cmd"].([]string)
		if !ok || !slices.Equal(argv, []string{"bin/tool", token}) || entry["cwd"] != "/work/"+token {
			t.Fatalf("audit did not redact command metadata: %v", entry)
		}
		if !slices.Equal(original.Argv, []string{"bin/tool", marker}) ||
			original.Cwd != "/work/"+marker || original.Argv0Path != "/work/"+marker+"/bin/tool" {
			t.Fatalf("redacting metadata changed the execution metadata: %+v", original)
		}
	})
}

func TestEscalationMetadataKeepsTheExecutionWorkingDirectory(t *testing.T) {
	cwd := filepath.Join(t.TempDir(), "synthetic-metadata-value")
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Command: config.DefaultCommand(), Secret: config.DefaultSecret(),
		Sudo:  config.SudoConfig{ExecUser: "test-executor", TimeoutSec: 10},
		Audit: config.AuditConfig{LogPath: filepath.Join(t.TempDir(), "audit.jsonl")},
	}
	s := New(nil, cfg)
	t.Cleanup(s.Escalation.Stop)
	called := false
	s.exec = func(_ *redact.Redactor, _ func(string), req execclient.Request) (*execclient.Result, error) {
		called = true
		if req.Cwd != cwd || req.RunID == "" {
			t.Fatalf("executor got cwd=%q runID=%q, want the original cwd and an escalation run", req.Cwd, req.RunID)
		}
		return &execclient.Result{}, nil
	}
	request := &protocol.Request{Cmd: []string{"/bin/true"}, Cwd: cwd, HasCwd: true}
	// Direct dispatch keeps the empty store in memory without a keeper refresh.
	response := s.opRun(request, nil, nil)
	if response["error"] != nil || !called {
		t.Fatalf("execution was not reached successfully: %v", response)
	}
	if request.Cwd != cwd {
		t.Fatalf("request cwd changed to %q, want %q", request.Cwd, cwd)
	}
}
