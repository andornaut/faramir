package broker

// Agent-facing responses.

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/keepertest"
	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/secretstore"
)

func TestListSecretsOmitsARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opListSecrets())
	if !strings.Contains(body, "faramir://good") {
		t.Errorf("a loaded ref is missing: %q", body)
	}
	if strings.Contains(body, "tiny") {
		t.Errorf("a refused ref was listed: %q", body)
	}
}

func TestListSecretsEndsEveryLine(t *testing.T) {
	s := newServer(t, map[string]string{
		"a": "hunter2-correct-horse", "b": "another-good-value",
	})
	body := output(t, s.opListSecrets())
	if body == "" {
		t.Fatal("empty output")
	}
	if !strings.HasSuffix(body, "\n") {
		t.Errorf("the last line is unterminated: %q", body)
	}
	for line := range strings.SplitSeq(strings.TrimSuffix(body, "\n"), "\n") {
		if !strings.HasPrefix(line, "faramir://") {
			t.Errorf("unexpected line: %q", line)
		}
	}
}

func TestListSecretsIsEmptyWhenNothingLoaded(t *testing.T) {
	s := newUnconfiguredServer(t, map[string]string{})
	if body := output(t, s.opListSecrets()); body != "" {
		t.Errorf("output = %q, want empty", body)
	}
}

// A value that is never tokenized is worth targeting, so status names neither
// it nor the operator-only refusal list.
func TestStatusDoesNotNameARefusedRef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	body := output(t, s.opStatus())
	if strings.Contains(body, "tiny") {
		t.Errorf("status named a refused ref: %q", body)
	}
	if strings.Contains(body, "not_redactable") {
		t.Errorf("status carried the refusal list: %q", body)
	}
	if !strings.Contains(body, "count") {
		t.Errorf("status is missing count: %q", body)
	}
	// It says a ref like that exists, which is what the exit status already
	// says: without it, status exits 1 and nothing anywhere gives a reason.
	// Counted, so what it adds is the number and not the name.
	if !strings.Contains(body, "cannot be redacted") {
		t.Errorf("status gives no reason for the status it exits with: %q", body)
	}
}

// The field that carries that reason: every state that leaves a configured ref
// not working or a configured value uncovered, counted. A caller reading it
// knows what is wrong and how much of it; `doctor` is where each is named.
func TestStatusSaysWhyItIsDegradedWithoutNamingARef(t *testing.T) {
	s := newServer(t, map[string]string{
		"good": "hunter2-correct-horse", "tiny": "abc",
	})
	var body struct {
		Degraded string `json:"degraded"`
	}
	if err := json.Unmarshal([]byte(output(t, s.opStatus())), &body); err != nil {
		t.Fatal(err)
	}
	if body.Degraded == "" {
		t.Fatal("a degraded store reports no reason")
	}
	for _, ref := range []string{"tiny", "good"} {
		if strings.Contains(body.Degraded, ref) {
			t.Errorf("the reason names %q: %s", ref, body.Degraded)
		}
	}
	if !strings.Contains(body.Degraded, "doctor") {
		t.Errorf("the reason does not say where the refs are named: %s", body.Degraded)
	}
	// And a store doing its whole job says nothing, so the field is a reason or
	// it is empty, never a sentence about being fine.
	healthy := newServer(t, map[string]string{"good": "hunter2-correct-horse"})
	if err := json.Unmarshal([]byte(output(t, healthy.opStatus())), &body); err != nil {
		t.Fatal(err)
	}
	if body.Degraded != "" {
		t.Errorf("a healthy store reports %q", body.Degraded)
	}
}

// One file is loaded, so status names it rather than reporting a list of one.
// The client reconstructs the config directory from this, so an install whose
// config was moved is found by what the broker answers rather than by the
// compiled-in default.
func TestStatusNamesTheOneConfigItLoaded(t *testing.T) {
	s := newServer(t, map[string]string{"a/b": "hunter2-correct-horse"})
	var body struct {
		Config string `json:"config"`
	}
	if err := json.Unmarshal([]byte(output(t, s.opStatus())), &body); err != nil {
		t.Fatalf("status is not JSON: %v", err)
	}
	if body.Config != s.Config.Path {
		t.Errorf("config = %q, want the loaded file %q", body.Config, s.Config.Path)
	}
}

// A link that did not load refuses one ref and leaves the broker serving, so
// nothing about a command's own failure says the host is degraded. The exit
// code is what carries it, and the body still prints.
func TestStatusExitsNonZeroOnADegradedLink(t *testing.T) {
	managed := managedFile(t)
	k := keepertest.New(t, map[string]string{"a/b": "hunter2-correct-horse"}, managed)
	s := serverWith(t, k, managed)
	s.Config.Secret.Links = []config.Link{{
		Ref: "npm/token", Path: filepath.Join(t.TempDir(), "gone"),
		Type: secretlink.KindText,
	}}
	s.Store = secretstore.New(s.Config.Secret, s.Config.Keeper)
	s.Store.Reload()

	response := s.opStatus()
	if code, _ := response["exit_code"].(int); code == 0 {
		t.Error("status exited 0 with a link that did not load")
	}
	body := output(t, response)
	if !strings.Contains(body, "npm/token") {
		t.Errorf("status does not name the degraded ref: %q", body)
	}
	// The path is the location of a credential, and this answer reaches the
	// agent. DescribeForOperator is what carries it.
	if strings.Contains(body, "gone") {
		t.Errorf("status carries the linked file's path: %q", body)
	}
	// Serving, not refusing: every other ref is unaffected.
	if reason := s.Store.Unreadable(); reason != "" {
		t.Errorf("a degraded link stopped the broker: %s", reason)
	}
}

func TestStatusNeverCarriesAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	if body := output(t, s.opStatus()); strings.Contains(body, secret) {
		t.Errorf("status leaked a value: %q", body)
	}
}

// An unexpected error string may have interpolated a value.
func TestSafeDetailRedactsAValue(t *testing.T) {
	const secret = "hunter2-correct-horse"
	s := newServer(t, map[string]string{"a/b": secret})
	got := s.safeDetail("exec failed: could not connect with " + secret)
	if strings.Contains(got, secret) {
		t.Errorf("an error message leaked a value: %q", got)
	}
	if !strings.Contains(got, "«SECRET:a/b»") {
		t.Errorf("no token in %q", got)
	}
}
