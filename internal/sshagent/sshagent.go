// Package sshagent runs an ssh-agent held by the broker, usable by children
// that cannot read its keys.
//
// Brokered commands run as faramir-exec.  The SSH keys that reach managed
// hosts have to be usable from there, and the obvious way to arrange that is
// to put them in that uid's home, at which point every brokered command can
// read them, and a leaked fleet key is permanent in a way a leaked password is
// not.
//
// So the broker keeps the key files under its own uid, loads them into an
// agent it owns, and passes only SSH_AUTH_SOCK to the child.  The child can
// authenticate to managed hosts for as long as the broker is running.  It
// cannot read the keys, and it cannot ptrace the agent, which belongs to
// another uid.
//
// Handing the child ssh-agent's own socket does not work, whatever its mode
// says: OpenSSH's ssh-agent calls getpeereid() on every connection and closes
// any whose peer euid is neither root nor its own, so the executor connects and
// then gets dropped mid-request.  ssh-agent therefore binds a private socket
// only the broker's uid uses, and the broker serves a second socket to the
// executor's group, relaying bytes between the two.  The relayed connection is
// the broker's own, so the uid check passes.  That also means ssh-agent no
// longer decides anything about the peer, so the relay does it instead: it
// makes the SO_PEERCRED check rather than leaving the socket's mode as the only
// boundary, and it forwards only the two requests the executor needs, because
// the same connection would otherwise let a brokered command empty the broker's
// agent or add a key to it.
//
// Entirely optional: with no [ssh] keys configured no agent is started and
// nothing is injected, and it is up to the operator to arrange authentication
// (usually by putting the keys in the executor's own home instead).
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
	// How many executor connections the proxy relays at once.  Each one costs
	// two descriptors in the broker for as long as it is open, and ssh holds
	// its agent connection for the whole of userauth, so the cap has to clear
	// the fork count of a real playbook run: ansible-playbook -f 100 authenticates
	// to a hundred hosts at once, and the excess would simply fail to authenticate.
	//
	// It bounds the broker's descriptor table, not fairness between brokered
	// commands.  One that opens connections and holds them can take every slot,
	// and the next command cannot authenticate until they close; that is a
	// brokered command denying service to itself, in a place the operator can
	// see in the journal, and it has far cheaper ways to do that.
	maxRelays = 256
	// How long a connection may sit without making its first request.  After
	// that it is a descriptor being held rather than an agent being used.  The
	// deadline is dropped once the first request arrives: an ssh session may
	// legitimately go hours between signatures.
	firstRequestTimeout = 30 * time.Second
	// ssh-agent's own limit on a single message.
	maxAgentMessage = 256 * 1024
)

// The two agent requests the executor may make: list the public halves, and
// sign with one of them.
const (
	agentRequestIdentities = 11
	agentSignRequest       = 13
)

// SSH_AGENT_FAILURE, framed.  What the protocol says to answer a request the
// agent will not carry out.
var agentFailure = []byte{0, 0, 0, 1, 5}

type Agent struct {
	config config.SshConfig
	cmd    *exec.Cmd
	// socket is the one the executor is given; private is the one ssh-agent
	// binds, which nothing but this process connects to.
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

func (a *Agent) Enabled() bool { return len(a.config.Keys) > 0 }

// Env is what to add to a child's environment.  Empty unless the agent runs.
func (a *Agent) Env() map[string]string {
	if a.socket == "" {
		return map[string]string{}
	}
	return map[string]string{"SSH_AUTH_SOCK": a.socket}
}

func (a *Agent) Start() {
	if !a.Enabled() {
		log.Printf("no [ssh] keys configured; not starting an agent")
		return
	}
	a.closing.Store(false)
	path := a.config.AgentSocket
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		log.Printf("cannot prepare %s: %v", path, err)
		return
	}
	private := path + ".private"
	for _, stale := range []string{path, private} {
		if err := removeStale(stale); err != nil {
			log.Printf("cannot prepare %s: %v", stale, err)
			return
		}
	}

	// -D keeps it in the foreground, so it is an ordinary child of this
	// process and dies with it rather than lingering with the keys loaded.
	cmd := exec.Command(a.config.SshAgent, "-D", "-a", private)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = nil, nil, nil
	if err := cmd.Start(); err != nil {
		log.Printf("cannot start %s: %v", a.config.SshAgent, err)
		return
	}
	a.cmd = cmd

	if !a.awaitSocket(private) {
		log.Printf("ssh-agent did not create %s; SSH keys will be unavailable", private)
		a.Stop()
		return
	}
	a.private = private

	// Before the executor can reach the proxy, so a brokered command never
	// finds an agent that is up and holding nothing.
	loaded := 0
	for _, key := range a.config.Keys {
		if a.add(key, private) {
			loaded++
		}
	}

	listener, err := listen(path)
	if err != nil {
		log.Printf("cannot serve %s: %v; SSH keys will be unavailable", path, err)
		a.Stop()
		return
	}
	a.listener = listener
	a.grantExecutorAccess(path)
	a.socket = path
	// private by value: Stop clears the field, and a connection accepted as it
	// runs would otherwise read it mid-write and dial "".
	go a.serve(listener, private)

	log.Printf("ssh-agent on %s with %d/%d key(s)", path, loaded, len(a.config.Keys))
	if loaded == 0 {
		log.Printf("no SSH keys loaded; commands needing SSH will fail to authenticate")
	}
}

func removeStale(path string) error {
	if _, err := os.Lstat(path); err != nil {
		return nil
	}
	return os.Remove(path)
}

// listen binds the proxy socket 0600, which grantExecutorAccess then widens to
// the configured mode and group.  Umask rather than a chmod afterwards: the
// mode is checked at connect time only, so a connection accepted in the window
// between bind and chmod would keep working for as long as it stayed open.
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
			// Returning here would leave a live socket that accepts nothing:
			// SSH_AUTH_SOCK still points at it, so a brokered command's connect
			// sits in the backlog until its own timeout instead of failing.
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
			// Refusing beats queueing: a brokered command gets an immediate
			// authentication failure it can report, rather than the broker
			// holding descriptors on its behalf until it runs out of them.
			log.Printf("ssh-agent proxy at %d connections; refusing another", maxRelays)
			_ = conn.Close()
		}
	}
}

// relay carries one executor connection to ssh-agent and back, one exchange at
// a time in this goroutine.
//
// The relay cannot be a blind byte pipe.  Every upstream connection is opened
// as the broker's uid, so ssh-agent's own getpeereid() no longer decides
// anything, and the agent protocol has no read-only mode: a connection that can
// sign can also send REMOVE_ALL_IDENTITIES or ADD_IDENTITY.  A brokered command
// could then empty the broker's agent, which breaks authentication to every
// managed host until the broker restarts, or load a key of its own into it.
// Listing and signing are what the executor needs; nothing else is forwarded.
//
// Filtering is why the exchange is serialized rather than two copies running in
// opposite directions: refusing a request means writing to the client, and a
// concurrent copy would interleave with it.  The protocol is request/response
// per connection, so nothing is lost by taking them in turn.
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
	// Stop closes what it finds here: with the client read below carrying no
	// deadline of its own, an idle connection would otherwise outlive the agent
	// it is a relay to.
	a.track(client)
	defer a.untrack(client)

	deadline := time.Now().Add(firstRequestTimeout)
	for {
		// A connection that never makes a request is a descriptor being held,
		// not an agent being used.  Only the first request is on the clock: an
		// ssh session may go hours between signatures.
		_ = client.SetReadDeadline(deadline)
		request, err := readMessage(client)
		if err != nil {
			return
		}
		deadline = time.Time{}

		if kind := request[4]; kind != agentRequestIdentities && kind != agentSignRequest {
			log.Printf("ssh-agent proxy: refusing agent request type %d; "+
				"brokered commands may list and sign only", kind)
			// The protocol's own refusal rather than a dropped connection: ssh
			// sends session-bind@openssh.com whenever agent forwarding is in
			// play, and a client that can see one request fail carries on
			// instead of losing the agent for the rest of the session.
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

// readMessage reads one length-prefixed agent message, header included, so that
// what is forwarded is what arrived.
func readMessage(conn net.Conn) ([]byte, error) {
	var header [4]byte
	if _, err := io.ReadFull(conn, header[:]); err != nil {
		return nil, err
	}
	length := binary.BigEndian.Uint32(header[:])
	// Neither is a message the other end could have meant, and forwarding the
	// second is how ssh-agent gets asked to allocate on demand.
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

// closeRelays drops every live executor connection.  Closing them outside the
// lock: each relay takes it on the way out.
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

// permitted is the SO_PEERCRED check every other faramir socket makes.
//
// The relayed connection is the broker's own, so ssh-agent's getpeereid() now
// passes whoever reaches this socket: agent_socket_mode is all that stands
// between an arbitrary uid and the fleet keys, and it is operator-supplied.
// The uid is therefore checked here, and a rejected connection is logged.
func (a *Agent) permitted(client net.Conn) bool {
	peer, err := sockutil.PeerCred(client)
	if err != nil {
		log.Printf("ssh-agent proxy: SO_PEERCRED unavailable: %v", err)
		return false
	}
	var groups []string
	if a.config.ExecGroup != "" {
		groups = []string{a.config.ExecGroup}
	}
	return sockutil.Allowed(peer, nil, nil, groups)
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

// grantExecutorAccess lets the executor's uid connect, and nothing else.
//
// listen binds the proxy socket 0600.  The chown needs the broker to be a
// member of the target group, which the unit arranges with SupplementaryGroups=.
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
	if err := os.Chmod(path, a.config.AgentSocketMode); err != nil {
		log.Printf("cannot set mode on %s: %v", path, err)
	}
}

func (a *Agent) add(key, socketPath string) bool {
	cmd := exec.Command(a.config.SshAdd, key)
	cmd.Env = []string{
		"SSH_AUTH_SOCK=" + socketPath,
		"PATH=/usr/local/bin:/usr/bin:/bin",
		"HOME=" + envOr("HOME", "/tmp"),
		// A key with a passphrase must fail immediately rather than block
		// startup waiting for input nobody will ever type.
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
		// Closing unlinks the socket, so the executor cannot reach an agent
		// that is going away.
		_ = a.listener.Close()
		a.listener = nil
	}
	// The socket being gone says nothing to a connection already established:
	// close those too, or a brokered command sits waiting on an agent that no
	// longer exists.
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

// lastLine is the most useful part of a failed command's output: the final
// line, which is where ssh-add puts its reason.
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
