package sshagent

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// Agent protocol message numbers, from draft-miller-ssh-agent.
const (
	msgFailure             = 5
	msgRemoveAllIdentities = 9
	msgRequestIdentities   = 11
	msgIdentitiesAnswer    = 12
	msgExtension           = 27
)

func requireSSH(t *testing.T) {
	t.Helper()
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not installed", bin)
		}
	}
}

// newKey mints an unencrypted ed25519 key for the agent to load.
func newKey(t *testing.T, dir string) string {
	t.Helper()
	path := filepath.Join(dir, "id_ed25519")
	cmd := exec.CommandContext(t.Context(), "ssh-keygen", "-t", "ed25519", "-N", "", "-C", "faramir-test", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	return path
}

func baseConfig(dir string) config.SshConfig {
	return config.SshConfig{
		AgentSocket: filepath.Join(dir, "ssh-agent.sock"),
		// The test runs as one uid, so there is no executor group to hand it to.
		ExecGroup: "",
		SshAgent:  "/usr/bin/ssh-agent", SshAdd: "/usr/bin/ssh-add",
	}
}

// -- disabled by default ----------------------------------------------------

// With no key, no agent is started and nothing is injected.
func TestNoKeyMeansNoAgentAndNoInjection(t *testing.T) {
	dir := t.TempDir()
	a := New(baseConfig(dir))
	if a.Enabled() {
		t.Error("Enabled with no key")
	}
	if err := a.Start(); err != nil {
		t.Errorf("Start with no key: %v, want nil", err)
	}
	defer a.Stop()

	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v, want empty", env)
	}
	if _, err := os.Stat(filepath.Join(dir, "ssh-agent.sock")); err == nil {
		t.Error("an agent socket was created with no key configured")
	}
}

// -- a configured key the agent cannot hold is fatal ------------------------

// A key is configured, so a host without the binary cannot serve it.
func TestAMissingBinaryIsAnError(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(dir)
	cfg.Key = filepath.Join(dir, "nope")
	cfg.SshAgent = filepath.Join(dir, "no-such-ssh-agent")

	a := New(cfg)
	err := a.Start()
	defer a.Stop()

	if err == nil {
		t.Fatal("Start = nil with an ssh-agent that does not exist")
	}
	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v after a failed start", env)
	}
}

// The config names a key and the disk has none, which is the drift that
// otherwise surfaces as a brokered command failing to authenticate.
func TestAConfiguredKeyThatIsNotOnDiskIsAnError(t *testing.T) {
	requireSSH(t)
	dir := t.TempDir()
	cfg := baseConfig(dir)
	cfg.Key = filepath.Join(dir, "id_ed25519")

	a := New(cfg)
	err := a.Start()
	defer a.Stop()

	if err == nil {
		t.Fatal("Start = nil with a configured key that is not on disk")
	}
	// Bound after the key loads, so a failure to load leaves nothing to reach.
	if _, statErr := os.Stat(cfg.AgentSocket); statErr == nil {
		t.Error("the proxy socket was bound with no key loaded")
	}
	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v after a failed start", env)
	}
}
