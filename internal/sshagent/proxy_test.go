package sshagent

// The proxy.

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

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
