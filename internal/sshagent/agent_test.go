package sshagent

// The agent, when it runs.

import (
	"encoding/binary"
	"io"
	"net"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"
)

func startedAgent(t *testing.T) (*Agent, string) {
	t.Helper()
	requireSSH(t)
	dir := t.TempDir()
	key := newKey(t, dir)
	cfg := baseConfig(dir)
	cfg.Key = key

	a := New(cfg)
	err := a.Start()
	t.Cleanup(a.Stop)
	// Fatal rather than skipped: requireSSH has already established that the
	// binaries are here, so a Start that fails now is this package's bug. Skipped
	// instead, it takes every proxy and relay test below with it and the suite
	// reports green having checked none of them.
	if err != nil {
		t.Fatalf("the agent did not start: %v", err)
	}
	if len(a.Env()) == 0 {
		t.Fatal("the agent started and handed the child nothing")
	}
	return a, key
}

// sshAdd runs ssh-add against the proxy, the only route to the agent here.
func sshAdd(t *testing.T, a *Agent, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "ssh-add", args...)
	cmd.Env = append(os.Environ(), "SSH_AUTH_SOCK="+a.Env()["SSH_AUTH_SOCK"])
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// dialProxy dials with a deadline, so a stuck relay fails rather than hangs.
func dialProxy(t *testing.T, sock string) net.Conn {
	t.Helper()
	client, err := (&net.Dialer{}).DialContext(t.Context(), "unix", sock)
	if err != nil {
		t.Fatalf("dial the proxy: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	if err := client.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return client
}

// request writes one agent message and reads the whole framed reply back.
func request(t *testing.T, client net.Conn, message ...byte) []byte {
	t.Helper()
	frame := append([]byte{0, 0, 0, byte(len(message))}, message...)
	if _, err := client.Write(frame); err != nil {
		t.Fatalf("write to the proxy: %v", err)
	}
	var header [4]byte
	if _, err := io.ReadFull(client, header[:]); err != nil {
		t.Fatalf("read the reply: %v", err)
	}
	body := make([]byte, binary.BigEndian.Uint32(header[:]))
	if _, err := io.ReadFull(client, body); err != nil {
		t.Fatalf("read the reply: %v", err)
	}
	return body
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
	out, err := sshAdd(t, a, "-l")
	if err != nil {
		t.Fatalf("ssh-add -l: %v: %s", err, out)
	}
	if !strings.Contains(out, "faramir-test") {
		t.Errorf("the key was not loaded: %s", out)
	}
}

// Whatever the mode ends up as, it must never be world-accessible.
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

// The agent lends authentication, not keys: the private half is never reachable
// through the socket.
func TestThePrivateKeyNeverAppearsInOutput(t *testing.T) {
	a, key := startedAgent(t)
	private, err := os.ReadFile(key)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.TrimSpace(string(private))

	out, _ := sshAdd(t, a, "-L")

	if strings.Contains(out, "PRIVATE KEY") || strings.Contains(out, body) {
		t.Error("the private key was reachable through the agent socket")
	}
}

// -D keeps the agent a child of the broker, so it dies with it.
func TestTheAgentDiesWithTheBroker(t *testing.T) {
	a, _ := startedAgent(t)
	sock := a.Env()["SSH_AUTH_SOCK"]
	private := a.private

	a.Stop()

	if _, err := os.Stat(sock); err == nil {
		t.Error("the agent socket outlived the broker")
	}
	if _, err := os.Stat(private); err == nil {
		t.Error("ssh-agent's own socket outlived the broker")
	}
	if env := a.Env(); len(env) != 0 {
		t.Errorf("Env = %v after Stop", env)
	}
}
