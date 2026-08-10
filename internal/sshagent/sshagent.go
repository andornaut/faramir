// Package sshagent runs an ssh-agent held by the broker, usable by children
// that cannot read its keys: the broker keeps the key files under its own uid
// and passes only SSH_AUTH_SOCK to the child.
//
// ssh-agent's own socket cannot be handed over, whatever its mode: it calls
// getpeereid() and drops any peer that is neither root nor itself.  So
// ssh-agent binds a private socket and the broker relays a second one to the
// executor's group.  The relayed connection is the broker's own, so ssh-agent
// no longer decides anything about the peer and the relay does it instead: it
// makes the SO_PEERCRED check and forwards only the two requests the executor
// needs.
//
// Optional: with no [ssh] key no agent is started and nothing is injected.
package sshagent

import (
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sockutil"
)

const (
	socketWait = 10 * time.Second
	// How many executor connections the proxy relays at once, each costing two
	// descriptors.  It has to clear a real playbook's fork count, since
	// ansible-playbook -f 100 authenticates to a hundred hosts at once.  It bounds
	// the broker's descriptor table, not fairness between commands.
	maxRelays = 256
	// How long a connection may sit before its first request.  Dropped once one
	// arrives: an ssh session may go hours between signatures.
	firstRequestTimeout = 30 * time.Second
	// ssh-agent's own limit on a single message.
	maxAgentMessage = 256 * 1024
	// The mode the proxy socket ends up with once its group is the executor's.
	// Not configurable: it is one half of a boundary whose other half is
	// exec_group, which init derives, and widening it here would admit accounts
	// no group names.
	socketMode = 0o660
)

// The two requests the executor may make: list the public halves, and sign.
const (
	agentRequestIdentities = 11
	agentSignRequest       = 13
)

// SSH_AGENT_FAILURE, framed.
var agentFailure = []byte{0, 0, 0, 1, 5}

type Agent struct {
	config config.SshConfig
	cmd    *exec.Cmd
	// socket is the executor's; private is ssh-agent's, reached only here.
	socket   string
	private  string
	listener net.Listener
	slots    chan struct{}
	closing  atomic.Bool

	// The live executor connections, so Stop can close them.
	mu    sync.Mutex
	conns map[net.Conn]struct{}
}

func New(cfg config.SshConfig) *Agent {
	return &Agent{
		config: cfg,
		slots:  make(chan struct{}, maxRelays),
		conns:  map[net.Conn]struct{}{},
	}
}

func (a *Agent) Enabled() bool { return a.config.Key != "" }

// Env is what to add to a child's environment.  Empty unless the agent runs.
func (a *Agent) Env() map[string]string {
	if a.socket == "" {
		return map[string]string{}
	}
	return map[string]string{"SSH_AUTH_SOCK": a.socket}
}

// Start brings the agent up and loads the configured key.  Failure is returned
// rather than logged, so the caller decides: the broker logs it and comes up,
// letting SSH fail where it is used, while `--check` and `doctor` fail on it.
//
// No key is not a failure.  That is the host where SSH is arranged for the
// executor's uid some other way.
func (a *Agent) Start() error {
	if !a.Enabled() {
		log.Printf("no [ssh] key configured; not starting an agent")
		return nil
	}
	a.closing.Store(false)
	path := a.config.AgentSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("cannot prepare %s: %w", path, err)
	}
	private := path + ".private"
	for _, stale := range []string{path, private} {
		if err := removeStale(stale); err != nil {
			return fmt.Errorf("cannot prepare %s: %w", stale, err)
		}
	}

	// -D keeps it a child of this process, so it dies with it rather than
	// lingering with the key loaded.
	cmd := exec.Command(a.config.SshAgent, "-D", "-a", private)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("cannot start %s: %w", a.config.SshAgent, err)
	}
	a.cmd = cmd

	if !a.awaitSocket(private) {
		a.Stop()
		return fmt.Errorf("%s did not create %s", a.config.SshAgent, private)
	}
	a.private = private

	// Before the socket is bound, so there is no window in which a command reaches
	// an agent holding nothing.  ssh-add has already logged why.
	if !a.add(a.config.Key, private) {
		a.Stop()
		return fmt.Errorf("the agent did not load %s, which [ssh] key names",
			a.config.Key)
	}

	listener, err := listen(path)
	if err != nil {
		a.Stop()
		return fmt.Errorf("cannot serve %s: %w", path, err)
	}
	a.listener = listener
	a.grantExecutorAccess(path)
	a.socket = path
	// private by value: Stop clears the field, and a connection accepted then
	// would read it mid-write.
	go a.serve(listener, private)

	log.Printf("ssh-agent on %s holding %s", path, a.config.Key)
	return nil
}

func removeStale(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	return os.Remove(path)
}

// listen binds the proxy socket 0600, which grantExecutorAccess widens.  Umask
// rather than a later chmod: the mode is checked only at connect time, so a
// connection accepted in between would keep working.
func listen(path string) (net.Listener, error) {
	previous := syscall.Umask(0o177)
	defer syscall.Umask(previous)
	return net.Listen("unix", path)
}

func (a *Agent) serve(listener net.Listener, private string) {
	delay := time.Duration(0)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if a.closing.Load() {
				return
			}
			// Returning would leave a live socket accepting nothing, so a command's
			// connect sits in the backlog until its own timeout.
			next, retry := sockutil.RetryAccept(err, delay)
			if !retry {
				log.Printf("ssh-agent proxy stopped accepting: %v", err)
				return
			}
			delay = next
			log.Printf("ssh-agent proxy could not accept (%v); retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		select {
		case a.slots <- struct{}{}:
			go func() {
				defer func() { <-a.slots }()
				a.relay(conn, private)
			}()
		default:
			// Refusing beats queueing: an immediate authentication failure the command
			// can report.
			log.Printf("ssh-agent proxy at %d connections; refusing another", maxRelays)
			_ = conn.Close()
		}
	}
}

// relay carries one executor connection to ssh-agent and back, one exchange at
// a time.
//
// Not a blind byte pipe: the agent protocol has no read-only mode, so a
// connection that can sign can also send REMOVE_ALL_IDENTITIES or ADD_IDENTITY.
// Only listing and signing are forwarded.
//
// Serialized because refusing a request means writing to the client, which a
// concurrent copy would interleave with.  The protocol is request/response per
// connection, so nothing is lost.
func (a *Agent) relay(client net.Conn, private string) {
	defer func() { _ = client.Close() }()
	if !a.permitted(client) {
		return
	}
	upstream, err := net.Dial("unix", private)
	if err != nil {
		log.Printf("ssh-agent proxy cannot reach %s: %v", private, err)
		return
	}
	defer func() { _ = upstream.Close() }()
	// Stop closes what it finds here; otherwise an idle connection outlives the
	// agent it relays to.
	a.track(client)
	defer a.untrack(client)

	deadline := time.Now().Add(firstRequestTimeout)
	for {
		// Only the first request is on the clock: an ssh session may go hours between
		// signatures.
		_ = client.SetReadDeadline(deadline)
		request, err := readMessage(client)
		if err != nil {
			return
		}
		deadline = time.Time{}

		if kind := request[4]; kind != agentRequestIdentities && kind != agentSignRequest {
			log.Printf("ssh-agent proxy: refusing agent request type %d; "+
				"brokered commands may list and sign only", kind)
			// The protocol's own refusal rather than a dropped connection: ssh sends
			// session-bind@openssh.com under agent forwarding, and a client that sees
			// one request fail carries on.
			if _, err := client.Write(agentFailure); err != nil {
				return
			}
			continue
		}

		if _, err := upstream.Write(request); err != nil {
			return
		}
		response, err := readMessage(upstream)
		if err != nil {
			return
		}
		if _, err := client.Write(response); err != nil {
			return
		}
	}
}

// readMessage reads one length-prefixed agent message, header included.
func readMessage(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	// Neither is a message the other end could have meant.
	if length == 0 || length > maxAgentMessage {
		return nil, fmt.Errorf("agent message of %d bytes", length)
	}
	message := make([]byte, 4+int(length))
	copy(message, header[:])
	if _, err := io.ReadFull(conn, message[4:]); err != nil {
		return nil, err
	}
	return message, nil
}

func (a *Agent) track(client net.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.conns[client] = struct{}{}
}

func (a *Agent) untrack(client net.Conn) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.conns, client)
}

// closeRelays drops every live executor connection, outside the lock: each
// relay takes it on the way out.
func (a *Agent) closeRelays() {
	a.mu.Lock()
	live := make([]net.Conn, 0, len(a.conns))
	for conn := range a.conns {
		live = append(live, conn)
	}
	clear(a.conns)
	a.mu.Unlock()
	for _, conn := range live {
		_ = conn.Close()
	}
}

// permitted is the SO_PEERCRED check every other faramir socket makes.  Since
// the relayed connection is the broker's own, ssh-agent's getpeereid() passes
// whoever reaches this socket, leaving socketMode and the socket's group as
// the only other boundary.
func (a *Agent) permitted(client net.Conn) bool {
	peer, err := sockutil.PeerCred(client)
	if err != nil {
		log.Printf("ssh-agent proxy: SO_PEERCRED unavailable: %v", err)
		return false
	}
	return sockutil.Allowed(peer, "", a.config.ExecGroup)
}

func (a *Agent) awaitSocket(path string) bool {
	deadline := time.Now().Add(socketWait)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(path); err == nil {
			return true
		}
		if a.cmd != nil && a.cmd.ProcessState != nil && a.cmd.ProcessState.Exited() {
			return false
		}
		time.Sleep(50 * time.Millisecond)
	}
	return false
}

// grantExecutorAccess lets the executor's uid connect, and nothing else.  The
// chown needs the broker in the target group, which the unit arranges with
// SupplementaryGroups=.
func (a *Agent) grantExecutorAccess(path string) {
	group := a.config.ExecGroup
	if group == "" {
		return
	}
	g, err := user.LookupGroup(group)
	if err != nil {
		log.Printf("group %s does not exist; the executor cannot use the agent", group)
		return
	}
	gid, err := strconv.Atoi(g.Gid)
	if err != nil {
		return
	}
	if err := os.Chown(path, -1, gid); err != nil {
		log.Printf("cannot hand %s to group %s (%v); is the broker a member of it?", path, group, err)
		return
	}
	if err := os.Chmod(path, socketMode); err != nil {
		log.Printf("cannot set mode on %s: %v", path, err)
	}
}

func (a *Agent) add(key, socketPath string) bool {
	cmd := exec.Command(a.config.SshAdd, key)
	cmd.Env = []string{
		"SSH_AUTH_SOCK=" + socketPath,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + envOr("HOME", "/tmp"),
		// A passphrase-protected key fails rather than blocking startup.
		"SSH_ASKPASS_REQUIRE=never",
		"DISPLAY=",
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		log.Printf("ssh-add %s failed: %v: %s", key, err, lastLine(string(out)))
		return false
	}
	return true
}

func (a *Agent) Stop() {
	a.closing.Store(true)
	if a.listener != nil {
		// Closing unlinks the socket.
		_ = a.listener.Close()
		a.listener = nil
	}
	// An established connection outlives the socket, so close those too.
	a.closeRelays()
	if a.cmd != nil && a.cmd.Process != nil {
		_ = a.cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = a.cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			_ = a.cmd.Process.Kill()
		}
	}
	a.cmd = nil
	for _, path := range []string{a.socket, a.private} {
		if path != "" {
			_ = os.Remove(path)
		}
	}
	a.socket = ""
	a.private = ""
}

func envOr(name, fallback string) string {
	if v := os.Getenv(name); v != "" {
		return v
	}
	return fallback
}

// lastLine is where ssh-add puts its reason.
func lastLine(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return "no output"
	}
	if i := strings.LastIndexByte(s, '\n'); i >= 0 {
		return s[i+1:]
	}
	return s
}
