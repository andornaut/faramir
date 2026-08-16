package e2e

// The approve CLI against a real broker socket.
//
// A broker alone, without the keeper, the executor or a delegated cgroup: the
// approval channel touches none of them, so this runs where the full harness
// skips.  What it covers is the wiring between the flags and the ops, which is
// the part no unit test reaches: `deny` with no id has to find the one question
// waiting, refuse it, and release the sudo blocked on it.

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/andornaut/faramir/internal/approval"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/server"
)

// approvalBroker is a broker serving the approval channel and nothing else.
func approvalBroker(t *testing.T) (*server.Server, string) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("the approval channel is root's, checked with SO_PEERCRED")
	}
	dir := t.TempDir()
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath:     filepath.Join(dir, "broker.sock"),
			MaxConcurrency: 4, MaxRequestBytes: 262144,
		},
		Sudo: config.SudoConfig{
			ExecUser: "faramir-exec", PamService: "faramir-sudo", TimeoutSec: 30,
		},
		Audit: config.AuditConfig{LogPath: filepath.Join(dir, "audit.log"), MaxRecordBytes: 1 << 20},
	}
	s := server.New(cfg)
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = s.Serve() }()
	t.Cleanup(func() { _ = s.Close() })
	return s, cfg.Server.SocketPath
}

// raise starts a run and puts its question, returning whether the sudo waiting
// on it was approved.
func raise(t *testing.T, s *server.Server, argv ...string) <-chan bool {
	t.Helper()
	token, heldBy := s.Approval.Register(approval.Run{Argv: argv, Cwd: "/srv"})
	if heldBy != "" || token == "" {
		t.Fatalf("the run was not registered (held by %q)", heldBy)
	}
	granted := make(chan bool, 1)
	go func() {
		approved, _ := s.Approval.Ask(token)
		granted <- approved
	}()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); {
		if len(s.Approval.Questions()) > 0 {
			return granted
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no question was raised")
	return nil
}

// `faramir deny` with no id refuses the one question waiting.  Only
// one is ever outstanding, so naming it adds a step and nothing else, and
// refusing something unseen is safe in a way approving it would not be.
func TestCLIDenyWithoutAnIDRefusesTheWaitingQuestion(t *testing.T) {
	s, sock := approvalBroker(t)
	granted := raise(t, s, "ansible-playbook", "site.yml")

	result := runCLI(t, sock, "deny")
	if result.code != 0 {
		t.Fatalf("code = %d, want 0\nstdout: %s\nstderr: %s",
			result.code, result.stdout, result.stderr)
	}
	// It says what it refused, so the operator's own scrollback holds the command
	// they turned down rather than an id alone.
	if !strings.Contains(result.stdout, "ansible-playbook site.yml") {
		t.Errorf("stdout does not name the command refused: %s", result.stdout)
	}
	if !strings.Contains(result.stdout, "refused") {
		t.Errorf("stdout does not say it was refused: %s", result.stdout)
	}
	if approved := <-granted; approved {
		t.Error("the sudo was approved by a deny")
	}
	if left := s.Approval.Questions(); len(left) != 0 {
		t.Errorf("%d questions still waiting after a refusal", len(left))
	}
}

// Nothing waiting is not an error, but it is not success either: a script has
// to be able to tell "refused one" from "there was nothing to refuse".
func TestCLIDenyWithNothingWaitingSaysSo(t *testing.T) {
	_, sock := approvalBroker(t)

	result := runCLI(t, sock, "deny")
	if result.code != 1 {
		t.Errorf("code = %d, want 1 with nothing waiting\nstderr: %s",
			result.code, result.stderr)
	}
	if !strings.Contains(result.stderr, "nothing is waiting") {
		t.Errorf("stderr does not say nothing was waiting: %s", result.stderr)
	}
}

// The machine-readable listing answers in JSON whether or not anything is
// waiting, so a caller parsing stdout always has a value to parse.  The status
// is what says which of the two it got, the array not having to.
func TestCLIListAsJSONIsAnArrayEitherWay(t *testing.T) {
	s, sock := approvalBroker(t)

	empty := runCLI(t, sock, "approvals", "--json")
	if empty.code != 1 {
		t.Errorf("code = %d, want 1 with nothing waiting\nstderr: %s",
			empty.code, empty.stderr)
	}
	var none []map[string]any
	if err := json.Unmarshal([]byte(empty.stdout), &none); err != nil {
		t.Fatalf("stdout is not JSON with nothing waiting: %q (%v)", empty.stdout, err)
	}
	if len(none) != 0 {
		t.Errorf("nothing is waiting, but the listing holds %d: %s", len(none), empty.stdout)
	}

	raise(t, s, "ansible-playbook", "site.yml")
	listed := runCLI(t, sock, "approvals", "--json")
	if listed.code != 0 {
		t.Fatalf("code = %d, want 0\nstderr: %s", listed.code, listed.stderr)
	}
	var questions []map[string]any
	if err := json.Unmarshal([]byte(listed.stdout), &questions); err != nil {
		t.Fatalf("stdout is not JSON: %q (%v)", listed.stdout, err)
	}
	if len(questions) != 1 {
		t.Fatalf("the listing holds %d questions, want 1: %s", len(questions), listed.stdout)
	}
	if cmd, _ := questions[0]["cmd"].(string); cmd != "ansible-playbook site.yml" {
		t.Errorf("the question does not name the command: %s", listed.stdout)
	}
}

// The listing form, for the same broker: it names the question, the id to
// answer with, and how long is left to do it in.
func TestCLIListNamesTheIDAndTheTimeLeft(t *testing.T) {
	s, sock := approvalBroker(t)
	raise(t, s, "ansible-playbook", "site.yml")

	result := runCLI(t, sock, "approvals")
	if result.code != 0 {
		t.Fatalf("code = %d, want 0\nstderr: %s", result.code, result.stderr)
	}
	for _, want := range []string{
		"ansible-playbook site.yml", "approve with: faramir approve",
		"refuse with:  faramir deny", "within",
	} {
		if !strings.Contains(result.stdout, want) {
			t.Errorf("stdout does not carry %q: %s", want, result.stdout)
		}
	}
}
