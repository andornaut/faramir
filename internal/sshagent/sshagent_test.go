package sshagent

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
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
	cmd := exec.Command("ssh-keygen", "-t", "ed25519", "-N", "", "-C", "faramir-test", "-f", path)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v: %s", err, out)
	}
	return path
}

func baseConfig(dir string) config.SshConfig {
	return config.SshConfig{
		AgentSocket: filepath.Join(dir, "ssh-agent.sock"), AgentSocketMode: 0o600,
		// The test runs as one uid, so there is no executor group to hand it to.
		ExecGroup: "",
		SshAgent:  "/usr/bin/ssh-agent", SshAdd: "/usr/bin/ssh-add",
	}
}

// -- disabled by default ----------------------------------------------------

// With no keys, no agent is started and nothing is injected: SSH then
// authenticates however the operator arranged it for the executor's uid.
func TestNoKeysMeansNoAgentAndNoInjection(t *testing.T) {
	dir := t.TempDir()
	a := New(baseConfig(dir))
	if a.Enabled() {
		t.Error("Enabled with no keys")
	}
	a.Start()
	defer a.Stop()

	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v, want empty", env)
	}
	if _, err := os.Stat(filepath.Join(dir, "ssh-agent.sock")); err == nil {
		t.Error("an agent socket was created with no keys configured")
	}
}

// A missing ssh-agent binary must be logged, not panic: SSH is optional.
func TestAMissingBinaryDoesNotRaise(t *testing.T) {
	dir := t.TempDir()
	cfg := baseConfig(dir)
	cfg.Keys = []string{filepath.Join(dir, "nope")}
	cfg.SshAgent = filepath.Join(dir, "no-such-ssh-agent")

	a := New(cfg)
	a.Start() // must not panic
	defer a.Stop()

	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v after a failed start", env)
	}
}

// -- the agent, when it runs ------------------------------------------------

func startedAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	requireSSH(t)
	dir := t.TempDir()
	key := newKey(t, dir)
	cfg := baseConfig(dir)
	cfg.Keys = []string{key}

	a := New(cfg)
	a.Start()
	t.Cleanup(a.Stop)
	if len(a.Env()) == 0 {
		t.Skip("ssh-agent did not come up in this environment")
	}
	return a, key
}

func TestChildrenGetSshAuthSock(t *testing.T) {
	a, _ := startedAgent(t)
	env := a.Env()
	sock, ok := env["SSH_AUTH_SOCK"]
	if !ok {
		t.Fatalf("Env = %v", env)
	}
	if len(env) != 1 {
		t.Errorf("Env carries more than the socket: %v", env)
	}
	if _, err := os.Stat(sock); err != nil {
		t.Errorf("socket %s: %v", sock, err)
	}
}

// The child can authenticate with the key; it never receives the key.
func TestTheKeyIsLoadedAndUsableThroughTheAgent(t *testing.T) {
	a, _ := startedAgent(t)
	cmd := exec.Command("ssh-add", "-l")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.Env()["SSH_AUTH_SOCK"])
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-add -l: %v: %s", err, out)
	}
	if !strings.Contains(string(out), "faramir-test") {
		t.Errorf("the key was not loaded: %s", out)
	}
}

// ssh-agent creates its socket 0600; whatever the mode ends up as, it must
// never be world-accessible.
func TestTheAgentSocketIsNotWorldAccessible(t *testing.T) {
	a, _ := startedAgent(t)
	info, err := os.Stat(a.Env()["SSH_AUTH_SOCK"])
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm&0o007 != 0 {
		t.Errorf("socket mode is %o; world has access", perm)
	}
}

// The agent lends authentication, not keys.  ssh-add -L prints public keys
// only, and the private half must never be reachable through the socket.
func TestThePrivateKeyNeverAppearsInOutput(t *testing.T) {
	a, key := startedAgent(t)
	private, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(private))

	cmd := exec.Command("ssh-add", "-L")
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.Env()["SSH_AUTH_SOCK"])
	out, _ := cmd.CombinedOutput()

	if strings.Contains(string(out), "PRIVATE KEY") || strings.Contains(string(out), body) {
		t.Error("the private key was reachable through the agent socket")
	}
}

// -D keeps the agent in the foreground, so it is an ordinary child that dies
// with the broker rather than lingering with the fleet keys loaded.
func TestTheAgentDiesWithTheBroker(t *testing.T) {
	a, _ := startedAgent(t)
	sock := a.Env()["SSH_AUTH_SOCK"]

	a.Stop()

	if _, err := os.Stat(sock); err == nil {
		t.Error("the agent socket outlived the broker")
	}
	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v after Stop", env)
	}
}
