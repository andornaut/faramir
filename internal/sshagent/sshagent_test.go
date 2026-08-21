package sshagent

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

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

// -- a configured key the agent cannot hold is fatal -----------------------

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

// -- the agent, when it runs ------------------------------------------------

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

// -- the proxy --------------------------------------------------------------

// OpenSSH closes any connection whose peer euid is not its own, so the executor
// arrives over one the broker opened.
func TestTheExecutorIsGivenTheProxyNotTheAgentSocket(t *testing.T) {
	a, _ := startedAgent(t)

	if a.private == "" {
		t.Fatal("no private socket was recorded")
	}
	if sock := a.Env()["SSH_AUTH_SOCK"]; sock == a.private {
		t.Errorf("ssh-agent's own socket was handed to the executor: %s", sock)
	}
	info, err := os.Stat(a.private)
	if err != nil {
		t.Fatal(err)
	}
	// Only the broker's uid connects here.
	if perm := info.Mode().Perm(); perm&0o077 != 0 {
		t.Errorf("ssh-agent's own socket is %o; it is reachable beyond the broker", perm)
	}
}

// When ssh-agent hangs up first, the relay closes the executor's end rather
// than leaving the child blocked on a reply that is not coming.
func TestTheRelayClosesTheClientWhenTheAgentGoesAway(t *testing.T) {
	a, _ := startedAgent(t)
	client := dialProxy(t, a.Env()["SSH_AUTH_SOCK"])

	// One complete request first, so the relay is established both ways and
	// nothing of the reply is left buffered.
	request(t, client, msgRequestIdentities)

	a.Stop()

	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("the client was left open after the agent went away: %v", err)
	}
}

// The protocol has no read-only mode: the connection that signs can also empty
// the agent, breaking authentication to every host until the broker restarts.
func TestTheExecutorCannotEmptyTheAgent(t *testing.T) {
	a, _ := startedAgent(t)

	if out, err := sshAdd(t, a, "-D"); err == nil {
		t.Errorf("ssh-add -D succeeded through the relay: %s", out)
	}

	out, err := sshAdd(t, a, "-l")
	if err != nil {
		t.Fatalf("ssh-add -l after the refused request: %v: %s", err, out)
	}
	if !strings.Contains(out, "faramir-test") {
		t.Errorf("the key did not survive the refused request: %s", out)
	}
}

// A key the executor chose must not end up in the broker's agent.
func TestTheExecutorCannotAddAKeyToTheAgent(t *testing.T) {
	a, _ := startedAgent(t)
	theirs := newKey(t, t.TempDir())

	if out, err := sshAdd(t, a, theirs); err == nil {
		t.Errorf("ssh-add of the executor's own key succeeded: %s", out)
	}

	out, _ := sshAdd(t, a, "-l")
	if strings.Count(out, "faramir-test") != 1 {
		t.Errorf("the agent holds more than the broker's own key: %s", out)
	}
}

// Answered, not thrown: ssh sends session-bind@openssh.com under agent
// forwarding, and a teardown would cost the client its agent for the session.
func TestARefusedRequestIsAnsweredAndTheConnectionSurvives(t *testing.T) {
	a, _ := startedAgent(t)
	client := dialProxy(t, a.Env()["SSH_AUTH_SOCK"])

	if reply := request(t, client, msgExtension); !bytes.Equal(reply, []byte{msgFailure}) {
		t.Errorf("reply = %v, want SSH_AGENT_FAILURE [%d]", reply, msgFailure)
	}

	// The same connection still lists identities.
	reply := request(t, client, msgRequestIdentities)
	if reply[0] != msgIdentitiesAnswer {
		t.Errorf("answer type = %d, want %d", reply[0], msgIdentitiesAnswer)
	}
}

// A relay that does not unwind holds its slot for good, and enough of them
// leave the proxy with none.
func TestRefusedRequestsDoNotExhaustTheRelaySlots(t *testing.T) {
	a, _ := startedAgent(t)
	sock := a.Env()["SSH_AUTH_SOCK"]
	// More than the cap, so a slot that is never released takes the proxy down.
	for range maxRelays + 4 {
		client := dialProxy(t, sock)
		request(t, client, msgRemoveAllIdentities) // which the relay refuses
		_ = client.Close()
		// The close above starts the unwind that releases the slot.
		for range 100 {
			if len(a.slots) == 0 {
				break
			}
			time.Sleep(10 * time.Millisecond)
		}
		if held := len(a.slots); held != 0 {
			t.Fatalf("%d relay slot(s) still held after a refused request", held)
		}
	}

	out, err := sshAdd(t, a, "-l")
	if err != nil || !strings.Contains(out, "faramir-test") {
		t.Errorf("the proxy stopped serving after refused requests: %v: %s", err, out)
	}
}

// The refusal above answers on the protocol and keeps the connection, so it
// must not also stop the clock: a peer that sends one refused message and then
// nothing would otherwise hold its relay slot for as long as the agent runs, and
// maxRelays of them leave the proxy with none. Only a request the proxy will
// actually forward means the connection is in use.
func TestARefusedRequestDoesNotClearTheFirstRequestTimeout(t *testing.T) {
	restore := firstRequestTimeout
	firstRequestTimeout = 150 * time.Millisecond
	t.Cleanup(func() { firstRequestTimeout = restore })

	a, _ := startedAgent(t)
	client := dialProxy(t, a.Env()["SSH_AUTH_SOCK"])

	// Blocked, answered, and the connection is still open.
	if reply := request(t, client, msgExtension); !bytes.Equal(reply, []byte{msgFailure}) {
		t.Fatalf("reply = %v, want SSH_AGENT_FAILURE [%d]", reply, msgFailure)
	}
	// Now send nothing. The deadline is still the one set when the connection
	// opened, so the relay unwinds on its own and gives the slot back.
	for range 100 {
		if len(a.slots) == 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if held := len(a.slots); held != 0 {
		t.Fatalf("%d relay slot(s) still held by a peer that only ever sent a refused request", held)
	}
	_ = client.Close()
}

// A request the proxy does forward is the connection being used, so the clock
// stops: an ssh session may go hours between signatures.
func TestAForwardedRequestClearsTheFirstRequestTimeout(t *testing.T) {
	restore := firstRequestTimeout
	firstRequestTimeout = 150 * time.Millisecond
	t.Cleanup(func() { firstRequestTimeout = restore })

	a, _ := startedAgent(t)
	client := dialProxy(t, a.Env()["SSH_AUTH_SOCK"])
	defer func() { _ = client.Close() }()

	if reply := request(t, client, msgRequestIdentities); reply[0] != msgIdentitiesAnswer {
		t.Fatalf("answer type = %d, want %d", reply[0], msgIdentitiesAnswer)
	}
	// Well past the timeout, idle throughout.
	time.Sleep(400 * time.Millisecond)
	if reply := request(t, client, msgRequestIdentities); reply[0] != msgIdentitiesAnswer {
		t.Errorf("the connection was dropped while idle between signatures: %v", reply)
	}
}

// Not a request the executor could have meant, and forwarding it asks ssh-agent
// to allocate on demand.
func TestAnOversizedMessageIsRefused(t *testing.T) {
	a, _ := startedAgent(t)
	client := dialProxy(t, a.Env()["SSH_AUTH_SOCK"])

	var header [4]byte
	binary.BigEndian.PutUint32(header[:], maxAgentMessage+1)
	if _, err := client.Write(header[:]); err != nil {
		t.Fatalf("write to the proxy: %v", err)
	}
	if _, err := client.Read(make([]byte, 1)); !errors.Is(err, io.EOF) {
		t.Errorf("the connection outlived an oversized message: %v", err)
	}
}

// A relay that works once and then wedges passes every install check.
func TestTheProxyServesMoreThanOneConnection(t *testing.T) {
	a, _ := startedAgent(t)
	for i := range 3 {
		out, err := sshAdd(t, a, "-l")
		if err != nil {
			t.Fatalf("ssh-add -l on connection %d: %v: %s", i+1, err, out)
		}
		if !strings.Contains(out, "faramir-test") {
			t.Fatalf("connection %d did not reach the key: %s", i+1, out)
		}
	}
}
