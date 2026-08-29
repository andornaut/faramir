// Package server is the broker daemon. Socket-activated by systemd
// (LISTEN_FDS), falling back to binding the socket itself when run standalone.
// Requests over [command] concurrency are refused rather than queued.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"math"
	"net"
	"os"
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/executor"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/resolve"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/secretstore"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/sshagent"
	"github.com/andornaut/faramir/internal/termsafe"
	"github.com/andornaut/faramir/internal/version"
)

type Server struct {
	Config     *config.Config
	Store      *secretstore.Store
	Audit      *audit.Log
	Ssh        *sshagent.Agent
	Escalation *escalation.Server

	// declared is what this host declares under [[secret.block]] and
	// [[secret.link]], compiled into the rules a brokered command is refused by.
	// See declared.go.
	declared declaredCheck

	// exec runs one command. A field so a test can substitute one that records
	// what it was handed, rather than reaching broker policy through a socket, a
	// PTY and a forked process.
	exec func(*redact.Redactor, func(string), executor.Request) (*executor.Result, error)

	slots chan struct{}
	ln    net.Listener
	wg    sync.WaitGroup

	// Every connection still being served, so Close can unblock the ones parked
	// on a peer. See Close.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

func New(cfg *config.Config) *Server {
	s := &Server{
		Config: cfg,
		// What this host declares, as the rules a brokered command is held to.
		// Compiled once: the entries change by `faramir block add` and `faramir
		// link add`, each of which rewrites the config and restarts what reads it.
		declared:   newDeclaredCheck(cfg.Secret, agentHomeDir(cfg.Server.AgentUser)),
		Store:      secretstore.New(cfg.Secret, cfg.Keeper),
		Audit:      audit.NewLog(cfg.Audit),
		Ssh:        sshagent.New(cfg.Ssh),
		Escalation: escalation.New(cfg.Sudo),
		slots:      make(chan struct{}, cfg.Command.Concurrency),
		exec: func(r *redact.Redactor, sink func(string), req executor.Request) (*executor.Result, error) {
			return executor.Run(cfg.Command, cfg.Executor, r, sink, req)
		},
	}
	// An escalation is recorded where every other op is. The record holds the
	// command and the answer, not a value: the audit log is written after
	// redaction.
	s.Escalation.Record = func(entry map[string]any) { s.Audit.Write(entry, audit.Output{}) }
	// The kernel's answer to the question the escalation server can only believe:
	// is anything running as the executor outside the run being approved? Asked
	// of the executor because ProtectProc=invisible keeps another uid's /proc out
	// of the broker's view, and failing closed.
	s.Escalation.Quiescent = func() (bool, string) {
		return execserver.Quiescent(cfg.Executor.SocketPath, quiescenceWait)
	}
	// Which run forked the process asking to sudo. Asked of the executor for the
	// same reason: it is the only party that knows what it forked, and the broker
	// cannot see another uid's /proc. Failing closed, an unattributable escalation
	// being the one thing this must never grant.
	s.Escalation.Owner = func(ancestors []int) (string, string) {
		return execserver.Owner(cfg.Executor.SocketPath, ancestors, quiescenceWait)
	}
	return s
}

// opRedactName is the one op a connection may carry more than one of, so it is
// named in the dispatch and again where the loop decides whether to continue.
const opRedactName = "redact"

// codeExecFailed answers every failure the executor reports, whatever code it
// named: what the caller can act on is that the command did not run.
const codeExecFailed = "exec_failed"

// The two exec failures a caller can branch on rather than read. A shell
// answers a program it could not find with 127 and one it found and could not
// run with 126, and `faramir run` gives the same numbers; `faramir redact --`
// runs its command itself and has always given them. Everything else stays
// exec_failed, which is the command not running for a reason worth reading.
const (
	codeNotFound      = "not_found"
	codeNotExecutable = "not_executable"
)

// codeBlocked is a command refused for what this host declares, under
// [[secret.block]] or [[secret.link]]. Terminal: nothing about the host will
// change to make the same command allowed, and a caller that retries is a
// caller reading the refusal as weather.
const codeBlocked = "blocked"

// splitExecCode takes the code the executor named off the front of its error.
// Only the codes it answers with: another message may carry a colon of its own,
// and cutting at the first one would take a clause with it.
func splitExecCode(text string) (string, string) {
	for _, code := range []string{codeNotExecutable, codeNotFound, codeExecFailed} {
		if rest, found := strings.CutPrefix(text, code+": "); found {
			return code, rest
		}
	}
	return codeExecFailed, text
}

// execFailureCode is which of the three a resolve failure was.
func execFailureCode(err error) string {
	switch {
	case errors.Is(err, resolve.ErrNotFound):
		return codeNotFound
	case errors.Is(err, resolve.ErrNotExecutable):
		return codeNotExecutable
	}
	return codeExecFailed
}

// quiescenceWait bounds the one round trip an escalation makes to the executor.
// Short: the answer is a /proc scan, and a human is waiting on it.
const quiescenceWait = 5 * time.Second

// peerWait bounds what a peer is given to send its request and to take its
// reply. It does not bound the op between them, which is a command running. A
// variable so a test can shorten it.
var peerWait = 30 * time.Second

func (s *Server) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(s.Config.Server.SocketPath)
	if err != nil {
		return nil, err
	}
	s.ln = ln
	return ln, nil
}

func (s *Server) Serve() error {
	delay := time.Duration(0)
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			next, retry := sockutil.RetryAccept(err, delay)
			if !retry {
				s.wg.Wait()
				return nil
			}
			delay = next
			log.Printf("broker could not accept (%v); retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
		s.wg.Go(func() {
			s.serveConnection(conn)
		})
	}
}

// Close stops the listener and unblocks every connection still being served.
// Serve waits on those goroutines, and what a connection waits on is a peer: a
// redact stream idling between chunks may sit in a read for [command]
// max_timeout_sec, so a deadline already past is what fails those reads at
// once.
//
// It does not reach a connection whose command is still running: that one is
// inside the executor rather than in socket I/O, and shutdown waits for it.
// Safe to call twice, which the daemon does.
func (s *Server) Close() error {
	// Before the deadlines below, and not left to the daemon's own defer: a
	// watcher's long poll is parked on a channel rather than on the socket, so a
	// deadline does not end it and Serve would wait out the poll. The defer runs
	// after Serve returns, which is too late to be what releases it.
	if s.Escalation != nil {
		s.Escalation.Stop()
	}
	s.connsMu.Lock()
	s.closing = true
	live := make([]net.Conn, 0, len(s.conns))
	for conn := range s.conns {
		live = append(live, conn)
	}
	s.connsMu.Unlock()
	for _, conn := range live {
		_ = conn.SetDeadline(time.Now().Add(-time.Second))
	}
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

// track registers a connection Close may need to unblock, and reports whether
// the server is still open: one accepted as Close ran would otherwise be served
// by a goroutine nothing is going to interrupt.
func (s *Server) track(conn net.Conn) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing {
		return false
	}
	if s.conns == nil {
		s.conns = map[net.Conn]struct{}{}
	}
	s.conns[conn] = struct{}{}
	return true
}

func (s *Server) untrack(conn net.Conn) {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	delete(s.conns, conn)
}

// extend pushes a connection's deadline out, and reports whether the server is
// still open. Taken under the lock Close sets `closing` in, so an extension
// either lands before Close's sweep or does not happen: set outside the lock it
// could land after the sweep and undo it, holding shutdown open.
func (s *Server) extend(conn net.Conn, d time.Duration, writeOnly bool) bool {
	s.connsMu.Lock()
	defer s.connsMu.Unlock()
	if s.closing {
		return false
	}
	if writeOnly {
		_ = conn.SetWriteDeadline(time.Now().Add(d))
	} else {
		_ = conn.SetDeadline(time.Now().Add(d))
	}
	return true
}

func (s *Server) serveConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	if !s.track(conn) {
		return // accepted as the broker was stopping
	}
	defer s.untrack(conn)

	// Both directions, and before the first refusal is written: a deadline on the
	// read alone leaves a peer that connects, asks and never reads blocked in
	// Write with nothing to time it out. A brokered command's output can reach
	// the output cap, well past a socket buffer, so the write blocks as soon as
	// the peer stops reading, and Serve waits on that goroutine to shut down.
	if !s.extend(conn, peerWait, false) {
		return // Close swept this connection between track and here
	}
	peer, err := s.peer(conn)
	if err != nil {
		_ = sockutil.Send(conn, protocol.ErrorResponse("forbidden", "peer not authorized", ""))
		return
	}

	// One connection carries one request, except a redact stream, which carries a
	// chunk at a time down the same one. The redactor holds back a tail longer
	// than the longest variant so a value split between two chunks is still
	// caught, and that tail is only useful to the chunk that follows.
	stream := &redactStream{}
	defer stream.finish(s, peer)

	// Buffered across iterations: a plain read would discard whatever it pulled
	// in past the newline, which for a stream is the start of the next chunk.
	lines := sockutil.NewLineReader(conn, config.MaxRequestBytes)

	for {
		line, err := lines.Next()
		if err != nil {
			if errors.Is(err, sockutil.ErrTooLarge) {
				_ = sockutil.Send(conn, protocol.ErrorResponse("too_large",
					fmt.Sprintf("request exceeds %d bytes", config.MaxRequestBytes), ""))
				return
			}
			if os.IsTimeout(err) {
				_ = sockutil.Send(conn, protocol.ErrorResponse("timeout", "no request received", ""))
			}
			return
		}
		if len(line) == 0 {
			return
		}

		var payload map[string]any
		if err := json.Unmarshal(line, &payload); err != nil {
			_ = sockutil.Send(conn, protocol.ErrorResponse("bad_request",
				fmt.Sprintf("invalid JSON: %v", err), ""))
			return
		}
		// Cleared for the op itself, which runs for as long as [command]
		// max_timeout_sec allows. The reply gets a fresh deadline once there is
		// something to write.
		_ = conn.SetDeadline(time.Time{})
		request, parseErr := protocol.Parse(payload)
		// Answered here rather than carried into the continue test below: Parse
		// returns no request alongside an error.
		if parseErr != nil {
			s.extend(conn, peerWait, true)
			_ = sockutil.Send(conn, protocol.ErrorResponse("bad_request", parseErr.Error(), ""))
			return
		}
		// Watched for the whole of a run, and only for a run: the caller holds
		// its write side open until it has the answer, so a read that fails
		// here is a caller that is gone rather than one that has finished
		// asking. A run nobody is waiting for is killed rather than left to its
		// timeout.
		response := s.dispatch(request, peer, stream, s.watchPeer(conn, request.Op))
		s.extend(conn, peerWait, true)
		if err := sockutil.Send(conn, response); err != nil {
			return
		}
		// The response decides as well as the request: a refused chunk ends the
		// connection rather than waiting out the long deadline below.
		if response["error"] != nil || request.Op != opRedactName || !request.More {
			return
		}
		// The next chunk of a stream already in progress is the only thing given
		// longer than peerWait: `faramir redact -- command` sends a chunk when the
		// command has printed one, and a quiet command is ordinary. Bounded by
		// what a brokered command may take, so an abandoned stream still ends.
		if !s.extend(conn, s.streamWait(), false) {
			return // the broker is stopping; the stream does not get another chunk
		}
	}
}

// streamWait bounds a redact stream between chunks.
func (s *Server) streamWait() time.Duration {
	return time.Duration(s.Config.Command.MaxTimeoutSec) * time.Second
}

// errPeerNotAllowed is a caller the socket admitted and the group check did
// not, which is a different failure from the kernel declining to say who the
// peer is.
var errPeerNotAllowed = errors.New("peer is not in the client group")

// peer performs the SO_PEERCRED check. The socket mode already restricts this
// to the client group; this also gives the audit log a real uid.
func (s *Server) peer(conn net.Conn) (*sockutil.Peer, error) {
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		return nil, err
	}
	cfg := s.Config.Server
	if !sockutil.Allowed(peer, "", cfg.AllowedGroup) {
		return nil, errPeerNotAllowed
	}
	return peer, nil
}

// Handle dispatches one request that stands on its own, which is every op but a
// chunked redact: those need the connection's state, so serveConnection parses
// and dispatches them itself. No connection to watch either, so a run through
// here is not one anything can abandon.
func (s *Server) Handle(payload map[string]any, peer *sockutil.Peer) protocol.Response {
	request, err := protocol.Parse(payload)
	if err != nil {
		return protocol.ErrorResponse("bad_request", err.Error(), "")
	}
	return s.dispatch(request, peer, nil, nil)
}

// watchPeer reports when the caller's connection goes, for the ops worth
// killing: a run, which may hold a concurrency slot for an hour. Everything
// else answers without running anything, so watching it would cost a goroutine
// per request to catch a window too short to be in.
//
// The read is what detects it. Nothing else is sent down this connection while
// a run is in flight, so it blocks until the peer closes, and the caller no
// longer half-closes its write side for exactly this reason.
//
// The goroutine outlives the run: serveConnection closes the connection on its
// way out, which is what ends the read. Whatever it decides then reaches
// nobody, the run having already returned.
func (s *Server) watchPeer(conn net.Conn, op string) <-chan struct{} {
	if op != protocol.OpRun {
		return nil
	}
	gone := make(chan struct{})
	go func() {
		// Read until it fails, rather than until it returns: bytes arriving are
		// a caller that is still here, whatever it sent. Killing the run on them
		// would answer a caller that spoke out of turn by taking its command
		// away. Nothing on this socket sends a second request down a connection
		// carrying a run, so they are discarded.
		var buf [64]byte
		for {
			_, err := conn.Read(buf[:])
			switch {
			case err == nil:
			// A deadline in the past is Close sweeping this connection, which is
			// the broker stopping rather than the caller leaving. The run ends
			// either way -- the executor tears down a run whose broker has gone,
			// which is what keeps an orphan from holding a credential -- and
			// this is about which reason is recorded. A stop is not a caller
			// walking away from its command.
			case os.IsTimeout(err):
				return
			default:
				close(gone)
				return
			}
		}
	}()
	return gone
}

// dispatch routes a parsed request. stream is the connection's redact state,
// nil for a caller that answers one request and is done with it.
func (s *Server) dispatch(request *protocol.Request, peer *sockutil.Peer,
	stream *redactStream, abandoned <-chan struct{}) protocol.Response {
	// Not on a chunk continuing a stream: that stream's redactor was built when
	// it started and is what the whole of it is scanned against, so a refresh
	// here would take a lock per chunk and change nothing.
	if stream == nil || stream.redactor == nil {
		s.Store.RefreshIfStale()
	}

	switch request.Op {
	case "status":
		return s.opStatus()
	case "refs":
		return s.opListSecrets()
	case opRedactName:
		return s.opRedact(request, peer, stream)
	case "refresh":
		return s.opRefresh(peer)
	case "escalations":
		return s.opEscalations(request, peer)
	case "answer":
		return s.opApprove(request, peer)
	case "escalate":
		return s.opEscalate(request, peer)
	default:
		return s.opRun(request, peer, abandoned)
	}
}

// opStatus answers what the broker loaded and what it can reach. Non-zero
// wherever the store is degraded, the body still printed: a ref the config names
// and the broker cannot answer is a host that is not what its config describes,
// and without an exit code to read, the first sign of it is a command failing
// later. Store.Degraded is the whole of that question; `faramir doctor` answers
// the same one and says what to do about each.
func (s *Server) opStatus() protocol.Response {
	// Whether, never a value: any member of the client group can ask, including
	// the coding agent, so what goes here lands in a model's context. It is also
	// the whole answer, a configured key that did not load looking identical to a
	// working one from the config's side.
	//
	// Describe carries the store's patterns and resolved files, which is where
	// rather than whether, and deliberately so: the config path below is 0644 and
	// its [secret] patterns already name the directory, so the file list is which
	// of those globs matched, not anything the agent could not already reach.
	configured, usable := s.Config.Ssh.Key != "", false
	if configured {
		data, err := os.ReadFile(s.Config.Ssh.Key)
		usable = err == nil && unusableReason(data) == ""
	}
	// Why the exit status below is what it is. Counted, never named: a ref in no
	// redactor is a value nothing tokenizes, and its name is what would make it
	// worth targeting. Empty on a store doing its whole job, so the field is
	// there either way and a caller reads one thing rather than inferring from a
	// status code with nothing beside it.
	document := map[string]any{
		"version": version.Version,
		// Which build, for the versions that do not name one. Empty for a
		// release, where the version is the answer.
		"build": version.Build,
		// The config file this broker loaded.
		"config":  s.Config.Path,
		"secrets": s.Store.Describe(),
		"ssh":     map[string]any{"configured": configured, "usable": usable},
		// Whether a brokered command may ask to sudo, which the agent needs to
		// know: without it a playbook touching this host has to leave it out.
		// Whether, not how.
		"sudo": map[string]any{"enabled": s.Escalation.Enabled()},
		// Named apart from secrets.errors, which is what a managed file said when
		// it did not load: this is every state that leaves a configured ref not
		// working or a configured value uncovered, which is the wider question.
		"degraded": s.Store.DegradedCounts(),
	}
	body, err := json.MarshalIndent(document, "", "  ")
	if err != nil {
		return protocol.ErrorResponse("internal", "the status could not be "+
			"rendered: "+err.Error(), "")
	}
	code := 0
	if s.Store.Degraded() != "" {
		code = 1
	}
	return okResponse(code, string(body)+"\n")
}

// opRedact scrubs text the caller already holds, so a session outside the
// broker's uid gets the same redaction a brokered command does. The value set
// never leaves this process. A deliberate oracle, and deliberately not
// rate-limited; docs/design.md has the weighting.
func (s *Server) opRedact(request *protocol.Request, peer *sockutil.Peer,
	stream *redactStream) protocol.Response {
	if stream == nil {
		// A caller with nowhere to keep the redactor cannot be part way through a
		// stream. Blocked rather than quietly completed: feeding text and never
		// flushing would drop the tail this chunk held back.
		if request.More {
			return protocol.ErrorResponse("bad_request",
				"'more' needs a connection that carries the stream", "")
		}
		stream = &redactStream{}
	}
	if stream.redactor == nil {
		if refused := s.refuseUnreadable("redact", "a redact", audit.NewLogID(), peer); refused != nil {
			return *refused
		}
		// Built once for the whole stream, so every chunk of one command's output
		// is scanned against one value set.
		stream.redactor = s.redactor()
		stream.logID = audit.NewLogID()
	}
	stream.inputBytes += len(request.Text)
	output := stream.redactor.Feed(request.Text)
	if !request.More {
		output += stream.redactor.Flush()
		stream.finish(s, peer)
	}
	response := okResponse(0, output)
	response["redactions"], response["log_id"] = stream.redactor.Summary(), stream.logID
	return response
}

// redactStream is what one connection's redact carries between chunks: the
// redactor, because the tail it holds back is only useful to the chunk that
// follows, and the totals for the one audit record the stream writes.
type redactStream struct {
	redactor   *redact.Redactor
	logID      string
	inputBytes int
	written    bool
}

// finish writes the stream's single audit record, at the end rather than per
// chunk: the counts only add up once the last chunk has been through. Called
// again from serveConnection for a stream the peer abandoned.
func (st *redactStream) finish(s *Server, peer *sockutil.Peer) {
	if st.redactor == nil || st.written {
		return
	}
	st.written = true
	s.Audit.Write(map[string]any{
		"log_id": st.logID, "op": "redact", "peer": peer,
		"input_bytes": st.inputBytes, "redactions": st.redactor.Summary(),
	}, audit.Output{})
}

// requireRoot gates the three escalation ops, the only ones this socket refuses
// to a caller it otherwise admits. Root, checked with SO_PEERCRED: not the
// client group, which holds the account the coding agent runs as, and not the
// executor, which is the side asking. Made in the op rather than left to a
// file mode, the socket admitting a group by design.
func (s *Server) requireRoot(op string, peer *sockutil.Peer) *protocol.Response {
	if peer != nil && peer.UID == 0 {
		return nil
	}
	out := protocol.ErrorResponse("forbidden", fmt.Sprintf(
		"%s is root's: an escalation must be answered by an account the coding "+
			"agent cannot become. Run `sudo faramir sudo ls`", op), "")
	return &out
}

// opRefresh re-reads the managed store now. Root's, because it is the operator
// commands that write the store: an agent asking would only be asking the
// broker to do sooner what it does on the interval anyway, at the cost of a
// decrypt per request.
//
// What it buys is the window between writing a value and the broker holding it,
// where the new value is in no redactor and a command that prints it prints it.
// `faramir vault` closes that itself rather than leaving it to the clock.
func (s *Server) opRefresh(peer *sockutil.Peer) protocol.Response {
	if peer == nil || peer.UID != 0 {
		return protocol.ErrorResponse("forbidden",
			"refresh is root's: it is what writes the managed store that asks for "+
				"it, and everything else is served by the refresh interval", "")
	}
	if !s.Store.Refresh(refreshWait) {
		// A reload already under way that did not finish in time. Refused rather
		// than answered, so the caller reports the interval it is now waiting on
		// instead of telling an operator the store has been re-read.
		return protocol.ErrorResponse("busy", fmt.Sprintf(
			"a reload was already running and did not finish within %s, so this "+
				"did not re-read the store; the refresh interval covers it", refreshWait), "")
	}
	refs := s.Store.Refs()
	response := okResponse(0, "")
	response["refs"] = refs
	return response
}

// refreshWait bounds what the refresh op waits for a reload already in flight.
// Under the caller's own deadline, so a caller that gives up first is the
// unusual case rather than the ordinary one.
const refreshWait = 90 * time.Second

// opEscalate is what sudo's PAM helper asks, and the only thing that decides
// whether a brokered command becomes root. It blocks until a human answers.
//
// Root, like the other two: the helper reaches it because pam_exec runs it with
// seteuid inside sudo. What it sends is an ancestry rather than anything it was
// given, so a caller has nothing to present and nothing to copy: the answer comes
// from comparing the kernel's account of who forked whom against what the
// executor forked.
func (s *Server) opEscalate(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("escalate", peer); refused != nil {
		return *refused
	}
	if len(request.Procs) == 0 {
		return protocol.ErrorResponse("bad_request",
			"'procs' must name the processes above the sudo asking to escalate", "")
	}
	approved, code, reason := s.Escalation.Ask(request.Procs)
	// A refusal is a response rather than an error: the helper reports it to PAM
	// as a failed authentication, which is what sudo has to see. The code rides
	// beside the reason, a refusal and an expiry reading alike in prose.
	response := okResponse(0, reason+"\n")
	response["approved"], response["reason"], response["outcome_code"] = approved, reason, code
	return response
}

func (s *Server) opEscalations(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("escalations", peer); refused != nil {
		return *refused
	}
	// Clamped in seconds, before the multiplication rather than after it: int64
	// nanoseconds run out somewhere past 292 years, so a large enough WaitSec
	// wraps negative and the min below keeps the negative. Poll would then return
	// at once on a request that asked to wait, which reads as a watcher that will
	// not hold. The parser bounds this below and not above, any non-negative
	// integer reaching here.
	wait := time.Duration(min(request.WaitSec, maxEscalationWaitSec)) * time.Second
	questions, finished := s.Escalation.Poll(wait, request.AwaitLogID)
	// Present only when the caller named a run and that run has ended, rather
	// than carrying a null nothing asked for.
	rendered := map[string]any{"questions": questions}
	if finished != nil {
		rendered["finished"] = finished
	}
	body, err := json.MarshalIndent(rendered, "", "  ")
	if err != nil {
		return protocol.ErrorResponse("internal", "the questions could not be "+
			"rendered: "+err.Error(), "")
	}
	response := okResponse(0, string(body)+"\n")
	response["questions"] = questions
	if finished != nil {
		response["finished"] = finished
	}
	return response
}

func (s *Server) opApprove(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("answer", peer); refused != nil {
		return *refused
	}
	// Named by the answering account rather than by uid alone: the audit record
	// is read by a person asking who let something through.
	who := fmt.Sprintf("uid %d", peer.UID)
	if entry, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		who = entry.Username
	}
	if peer.PID > 0 {
		who = fmt.Sprintf("%s (pid %d)", who, peer.PID)
	}
	if err := s.Escalation.Answer(request.ID, request.Approve, who); err != nil {
		// A yes turned into a no for want of a quiet host means run the command
		// again; an id nobody is waiting on means the question had already gone.
		if errors.Is(err, escalation.ErrNotQuiescent) {
			return protocol.ErrorResponse("not_quiescent", err.Error(), "")
		}
		return protocol.ErrorResponse("unknown_question", err.Error(), "")
	}
	verdict := "refused"
	if request.Approve {
		verdict = "approved"
	}
	return okResponse(0, request.ID+" "+verdict+"\n")
}

// maxEscalationWait bounds a watcher's long poll. It returns an empty list and
// the watcher asks again, so a broker restarted under it is noticed.
//
// In seconds as well, for the clamp in opEscalations: a caller's WaitSec is a
// count of seconds, and holding it to this before it becomes a Duration is what
// keeps the multiplication from wrapping.
const (
	maxEscalationWaitSec = 60
	maxEscalationWait    = maxEscalationWaitSec * time.Second
)

func (s *Server) opListSecrets() protocol.Response {
	// Names only, and only refs that loaded: a value the redactor cannot cover is
	// refused at load.
	refs := s.Store.Refs()
	var output strings.Builder
	for _, ref := range refs {
		output.WriteString("faramir://" + ref + "\n")
	}
	response := okResponse(0, output.String())
	response["refs"] = refs
	return response
}

// refuseUnreadable is the gate on the two ops whose output is redacted against
// the value set; see Store.Unreadable. Asked here rather than at startup: a
// startup check judges the host as it was at boot, and exiting would take the
// daemon down just when `faramir status` and `doctor` would explain why.
// status and refs stay available, neither producing output that depends on the
// set.
func (s *Server) refuseUnreadable(op, phrase, logID string, peer *sockutil.Peer) *protocol.Response {
	reason := s.Store.Unreadable()
	if reason == "" {
		return nil
	}
	log.Printf("%s refusing %s: %s", logID, phrase, reason)
	// Recorded like a served call: a refusal is what the operator is looking for
	// when they ask why nothing ran.
	s.Audit.Write(map[string]any{
		"log_id": logID, "op": op, "refused": "no_secrets", "reason": reason,
		// Who was refused, as every other record carries it. Without it this is
		// the one refusal in the log that says what happened and not to whom, and
		// a store that cannot be read produces a run of them.
		"peer": peer,
	}, audit.Output{})
	// The remedies are for the states that reach here, which are a managed file
	// that was found and did not load, and a keeper that never answered. A store
	// nobody has written yet is not one of them: Store.Unreadable serves that
	// case rather than refusing it, so advice about writing a first file was
	// advice for a condition this message cannot carry.
	out := protocol.ErrorResponse("no_secrets", fmt.Sprintf(
		"the broker does not hold every managed value, so %s would run with "+
			"redaction covering less than the config asks for: %s. What did not load "+
			"is named above and `sudo faramir doctor` says what to do about each; a "+
			"file the keeper cannot decrypt is usually its age key or its "+
			"recipients. Where the reason names a [[secret.link]] ref, that entry "+
			"claims a name the managed store already defines and `sudo faramir link "+
			"rm REF` is what clears it", phrase, reason), logID)
	return &out
}

// refuse answers a request that will not run, and records it under the log_id
// the caller is given: `faramir run` prints that id, so one naming
// no record sends somebody to look up nothing. Not for the refusals decided
// before a request is parsed -- too_large, a forbidden peer, malformed JSON --
// which carry no id.
func (s *Server) refuse(code, message, logID string, peer *sockutil.Peer,
	cmd []string, cwd string) protocol.Response {
	record := s.redactor()
	detail := record.RedactText(message)
	entry := map[string]any{
		"log_id": logID, "op": recordRun, "peer": peer,
		"refused": code, "error": detail,
	}
	if len(cmd) > 0 {
		entry["cmd"] = redactEach(record, cmd)
	}
	if cwd != "" {
		entry["cwd"] = record.RedactText(cwd)
	}
	s.Audit.Write(entry, audit.Output{})
	return protocol.ErrorResponse(code, detail, logID)
}

// refuseUnauditable is the gate on running anything at all: a command that
// cannot be recorded is not run, and the agent can reach that state by printing
// enough to fill the filesystem. Nothing is recorded here, there being nowhere
// to record it: the refusal goes back to the caller and to the daemon log.
// privateTmpDirs are the directories every unit gets a private copy of, so a
// path under one is the daemon's own and not the caller's.
var privateTmpDirs = []string{"/tmp", "/var/tmp", "/dev/shm"}

// cwdMissing explains a working directory the broker cannot find, and names the
// one reason it goes missing while the caller is looking straight at it: every
// faramir unit runs with PrivateTmp=true, so the daemon's /tmp, /var/tmp and
// /dev/shm are its own and hold nothing the caller put there.
//
// Without this the message is "cwd does not exist" about a directory the caller
// just made and can list, which reads as a bug in the broker rather than as the
// boundary it is. Scratch under /tmp is the obvious place to put a working
// directory, so this is met by anyone who tries it.
func cwdMissing(cwd string) string {
	for _, private := range privateTmpDirs {
		if cwd != private && !strings.HasPrefix(cwd, private+"/") {
			continue
		}
		return "cwd does not exist for this daemon: " + cwd + ". Every faramir unit " +
			"runs with PrivateTmp=true, so " + private + " here is the daemon's own " +
			"and holds nothing you put in yours. Name a directory outside " +
			strings.Join(privateTmpDirs, ", ") + "."
	}
	return "cwd does not exist: " + cwd
}

func (s *Server) refuseUnauditable(phrase, logID string) *protocol.Response {
	reason := s.Audit.Unwritable()
	if reason == "" {
		return nil
	}
	log.Printf("%s refusing %s: the audit log cannot be written: %s", logID, phrase, reason)
	out := protocol.ErrorResponse("no_audit",
		"the audit log cannot be written, so "+phrase+" was refused rather than "+
			"run unrecorded: "+reason+". Free space on that filesystem, or point "+
			"[audit] log_path somewhere with room, and retry", logID)
	return &out
}

// The two ops a brokered command's records carry. recordRunStarted is written
// when the child runs; recordRun is every other record about that command. The
// pair is joined by the log_id, so a reader selecting recordRun still gets one
// record per command.
const (
	recordRun        = "run"
	recordRunStarted = "run_started"
)

// callerName renders the peer as a person reads it: the name where the account
// still exists, and the uid either way, a name being reusable and an account
// removable while a question is still on somebody's screen.
func callerName(peer *sockutil.Peer) string {
	if peer == nil {
		return ""
	}
	if entry, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		return fmt.Sprintf("%s (uid %d)", entry.Username, peer.UID)
	}
	return fmt.Sprintf("uid %d", peer.UID)
}

// execEscalation is what the escalation server has to say about a run that has
// ended: whether a sudo inside it was turned down, and how much of its duration
// was the question rather than the command.
type execEscalation struct {
	// code and reason are the last no a sudo was given, empty where it was given
	// none: sudo reports a refusal and an expiry alike, as its own authentication
	// failure.
	code, reason string
	// waited is seconds the child spent blocked inside sudo. The duration is
	// wall time from fork to exit, so an escalation answered slowly reads as a
	// slow command without it.
	waited float64
}

func (s *Server) escalationOf(runID string) execEscalation {
	code, reason := s.Escalation.Refusal(runID)
	return execEscalation{code: code, reason: reason, waited: s.Escalation.Waited(runID).Seconds()}
}

// fields is what a record carries of it, each present only where it says
// something.
func (a execEscalation) fields() map[string]any {
	out := map[string]any{}
	if a.code != "" {
		out["escalation_code"], out["escalation"] = a.code, a.reason
	}
	if a.waited > 0 {
		out["waited_sec"] = math.Round(a.waited*1000) / 1000
	}
	return out
}

// execResponse is what the caller is told about a command that ran. What the
// escalation has to say rides along, each field present only where it says
// something.
// addRunConditions sets the audit-record fields that a run carries only when
// they say something, keeping a zero off every record.
func addRunConditions(record map[string]any, result *executor.Result) {
	// Both mean the recorded output is not what the command wrote.
	if result.InvalidBytes > 0 {
		record["invalid_bytes"] = result.InvalidBytes
	}
	// The record is the whole of what is left of an abandoned run: the response
	// goes to a connection nobody is reading.
	if result.Abandoned {
		record["abandoned"] = true
	}
	// The exit code is a stand-in: the executor went away before reporting a
	// status, so the log does not read the code as a signal kill.
	if result.StatusUnknown {
		record["status_unknown"] = true
	}
}

// okResponse is the base success shape every op answers with, the five keys
// docs/protocol.md documents; an op adds its own beside them, and the run op
// builds its response from the executor's result instead. log_id is JSON null
// where a response has no record to cite.
func okResponse(exitCode int, output string) protocol.Response {
	return protocol.Response{
		"exit_code": exitCode, "output": output, "truncated": false,
		"redactions": []any{}, "log_id": nil,
	}
}

func execResponse(logID string, judged execEscalation,
	result *executor.Result) protocol.Response {
	response := protocol.Response{
		"exit_code": result.ExitCode, "output": result.Output,
		"truncated": result.Truncated, "redactions": result.Redactions,
		"log_id": logID, "timed_out": result.TimedOut,
		"duration_sec":  result.DurationSec,
		"invalid_bytes": result.InvalidBytes,
	}
	// Only when set: the exit code is a stand-in for a status the executor never
	// reported, so a caller is told the code is a guess rather than a signal kill.
	if result.StatusUnknown {
		response["status_unknown"] = true
	}
	maps.Copy(response, judged.fields())
	return response
}

// execAudit is what every record about one brokered command carries: which
// command, run where, against which refs, and when it started. Gathered once
// and rendered per record, so the pair sharing a log_id cannot disagree.
type execAudit struct {
	logID     string
	peer      *sockutil.Peer
	cmd       []string
	argv0Path string
	cwd       string
	refs      map[string]string
	started   time.Time
}

// execFields is one record's worth of those, less the op and the outcome, which
// are the caller's to add. Redacted afresh per record: the value set can change
// while a command runs.
func (s *Server) execFields(a execAudit) map[string]any {
	record := s.redactor()
	return map[string]any{
		"log_id": a.logID, "peer": a.peer,
		"cmd":        redactEach(record, a.cmd),
		"argv0_path": record.RedactText(a.argv0Path),
		"cwd":        record.RedactText(a.cwd),
		"env_refs":   a.refs,
		"started_at": a.started.Unix(),
	}
}

func (s *Server) opRun(request *protocol.Request, peer *sockutil.Peer,
	abandoned <-chan struct{}) protocol.Response {
	execCfg := s.Config.Command
	logID := audit.NewLogID()
	if refused := s.refuseUnreadable("run", "this command", logID, peer); refused != nil {
		return *refused
	}
	if refused := s.refuseUnauditable("this command", logID); refused != nil {
		return *refused
	}

	cmd, envRefs := request.Cmd, request.EnvRefs

	// No fallback: a brokered command runs where its caller was, and nothing else
	// knows where that is.
	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		return s.refuse("bad_request", "no cwd: name the directory to run in.",
			logID, peer, cmd, "")
	}
	// Fails early with a clear message; it enforces nothing. Permission is left
	// to the executor, whose uid may hold traversal the broker does not. Absence
	// is refused here, being knowable from any uid, though not from every mount
	// namespace: see cwdMissing.
	info, statErr := os.Stat(cwd)
	switch {
	case statErr == nil && !info.IsDir():
		return s.refuse("bad_request", "cwd is not a directory: "+cwd, logID, peer, cmd, cwd)
	case os.IsPermission(statErr):
		// The executor decides.
	case statErr != nil:
		return s.refuse("bad_request", cwdMissing(cwd), logID, peer, cmd, cwd)
	}

	// Before the program is resolved and before a slot is taken: this is a
	// refusal about what the command would disclose, not about whether it could
	// have run. The agent's own tools are already refused what this host
	// declares, and the broker is the one route left to the file.
	if rule, refused := s.declared.refuses(cmd, cwd); refused {
		return s.refuse(codeBlocked, declaredRefusal(rule), logID, peer, cmd, cwd)
	}

	argv0Path, err := resolve.Program(cmd[0], cwd, execCfg)
	if err != nil {
		// Redacted like every other agent-visible string.
		record := s.redactor()
		detail := record.RedactText(err.Error())
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": recordRun, "peer": peer,
			"cmd": redactEach(record, cmd), "cwd": record.RedactText(cwd),
			"error": detail,
		}, audit.Output{})
		return protocol.ErrorResponse(execFailureCode(err), detail, logID)
	}

	// The only place plaintext is touched outside the store, and it goes straight
	// into the child's environ. HOME is left to the executor.
	env := make(map[string]string, len(execCfg.Env)+1)
	maps.Copy(env, execCfg.Env)
	// SSH_AUTH_SOCK: the child can authenticate with the keys, not read them.
	maps.Copy(env, s.Ssh.Env())
	// The concurrency slot first, and before the run is registered: Answer counts
	// a registered run as an occupant and refuses to approve alongside it, so a
	// run about to be refused `busy` must never be one.
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return s.refuse("busy", fmt.Sprintf(
			"broker is at its concurrency limit (%d); retry shortly",
			s.Config.Command.Concurrency), logID, peer, cmd, cwd)
	}

	// An id and nothing else: it goes to the executor, never into the child's
	// environment, so there is nothing inside the run to read, copy or leak.
	// FARAMIR_OPERATOR below is not part of it -- it names the host's operator,
	// which is not a secret and attributes nothing.
	// Registered before the child starts and dropped when it ends, so a late
	// request is refused rather than answered against a finished command.
	//
	// The argv is the redacted one, this reaching a terminal and the log. One
	// redactor for the whole question; the audit write below builds its own,
	// against whatever the store holds by then.
	asked := s.redactor()
	runID, heldBy := s.Escalation.Register(escalation.Run{
		Argv: redactEach(asked, cmd), Cwd: cwd, LogID: logID,
		// Who asked, which the executor's own uid does not say: every brokered
		// command runs as that one.
		Caller: callerName(peer),
		// What root would actually run, which is not always what argv[0] says: a
		// relative argv[0] resolves against the request's cwd, which is the agent's
		// working tree. The question names both when they differ.
		Argv0Path: asked.RedactText(argv0Path),
	})
	// Held while an escalation is live or a question is waiting: the two commands
	// share the executor's uid, so running this one now would give it a route to
	// the root the other was approved for.
	//
	// A terminal refusal rather than a `busy` to retry: a retryable answer makes
	// a caller poll the one window in which the host must be quiet, landing its
	// retries against the exact interval the serialisation protects.
	if heldBy != "" {
		// heldBy is a whole clause, naming the command and which of the two states
		// it is in: waiting to be approved, or holding an approval already given.
		// Framing it as a noun phrase spliced a second sentence into the first.
		return s.refuse("escalation_in_progress", heldBy+
			", and no other brokered command runs while one is: "+
			"a second could ride it. Not run and not queued; run it again once that "+
			"one has finished", logID, peer, cmd, cwd)
	}
	// How this run ended, read by the defer below and published to the terminal
	// that approved it. The zero value is a run the broker never got a status
	// for and says so: a nil ExitCode prints as an ending without one, where a
	// zero would print as a clean exit.
	outcome := escalation.Outcome{LogID: logID}
	defer func() { s.Escalation.Release(runID, outcome) }()
	// Who the host belongs to. Reserved, so a caller cannot name a different
	// account, and set on both sides of a sudo: the same value goes into the
	// grant's env_file, because sudo's env_reset would otherwise drop it exactly
	// where a command most needs to resolve the operator's home.
	if s.Config.Server.AgentUser != "" {
		env[protocol.OperatorEnv] = s.Config.Server.AgentUser
	}
	injected, why := s.inject(env, envRefs)
	if why != "" {
		// inject fills env ref by ref and can fail on a later one, so earlier
		// values are already in the map: drop them here rather than leave plaintext
		// referenced until the map is collected, as the post-exec cleanup does.
		for k := range env {
			delete(env, k)
		}
		return s.refuse("unknown_secret", why, logID, peer, cmd, cwd)
	}

	timeout := clampTimeout(request.TimeoutSec, execCfg)

	// Every known secret, not only the injected ones: a managed host can print one
	// the broker never injected.
	redactor := s.redactor()
	collector := audit.NewCollector(s.Audit.OutputBudget())
	started := time.Now()

	audited := execAudit{
		logID: logID, peer: peer, cmd: cmd, argv0Path: argv0Path,
		cwd: cwd, refs: injected, started: started,
	}

	// An exec is a pair of records sharing one log_id: this one when the child
	// starts, and the one below when it ends. Without it a command is absent
	// from the log for as long as it runs, and a run that never returns leaves
	// nothing at all. No output: there is none yet.
	starting := s.execFields(audited)
	starting["op"] = recordRunStarted
	s.Audit.Write(starting, audit.Output{})

	result, err := s.exec(redactor, collector.Add, executor.Request{
		Argv:       append([]string{argv0Path}, cmd[1:]...),
		Cwd:        cwd,
		Env:        env,
		TimeoutSec: timeout,
		RunID:      runID,
		Abandoned:  abandoned,
	})
	// Drop the plaintext as soon as the child has it; the store keeps the values.
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		// The executor names its own code in the error it returns. Taken off the
		// front rather than printed twice ("exec_failed: exec_failed:
		// /usr/bin/pwd: ..."), and carried rather than flattened: a program the
		// kernel would not run is answered as not_executable, which is what gets
		// the caller the shell's 126.
		code, text := splitExecCode(err.Error())
		detail := s.safeDetail(text)
		// Rendered on top of the redaction, which covers values and not control
		// characters: this string reaches the escalation terminal, where the next
		// thing printed is a question somebody judges.
		outcome.Error = termsafe.Line(detail)
		// The child ran whatever failed afterwards, so it is recorded before the
		// error is returned: otherwise a command that reached a managed host leaves
		// nothing behind but a daemon-log line.
		record := s.execFields(audited)
		record["op"], record["error"] = recordRun, detail
		s.Audit.Write(record, collector.Output())
		return protocol.ErrorResponse(code, detail, logID)
	}

	// Read before the deferred Release drops the run.
	judged := s.escalationOf(runID)

	outcome.ExitCode = &result.ExitCode
	outcome.DurationSec, outcome.TimedOut = result.DurationSec, result.TimedOut
	outcome.WaitedSec, outcome.StatusUnknown = judged.waited, result.StatusUnknown

	record := s.execFields(audited)
	record["op"] = recordRun
	record["exit_code"], record["duration_sec"] = result.ExitCode, result.DurationSec
	record["timed_out"], record["redactions"] = result.TimedOut, result.Redactions
	addRunConditions(record, result)
	maps.Copy(record, judged.fields())
	s.Audit.Write(record, collector.Output())

	total := 0
	for _, r := range result.Redactions {
		total += r.Count
	}
	log.Printf("%s %s exit=%d dur=%.1fs redactions=%d",
		logID, filepath.Base(argv0Path), result.ExitCode, result.DurationSec, total)

	return execResponse(logID, judged, result)
}

// inject puts the requested values into the child's environment and returns
// what each name was filled from, for the audit record: the refs, never the
// values. The string is why a ref could not be filled, empty where every one
// was.
//
// A failure stops at the ref that caused it, so env may already hold the values
// named before it. Nothing runs with them: the caller answers a non-empty
// reason with a refusal, and the map goes no further.
func (s *Server) inject(env map[string]string, envRefs map[string]string) (map[string]string, string) {
	injected := map[string]string{}
	for name, uri := range envRefs {
		ref, err := secretref.Parse(uri)
		if err != nil {
			return nil, err.Error()
		}
		value, err := s.Store.Value(ref)
		if err != nil {
			return nil, err.Error()
		}
		env[name] = value
		injected[name] = ref
	}
	return injected, ""
}

// clampTimeout is what this run actually gets: what it asked for, the config's
// default where it asked for nothing, and never more than the ceiling.
func clampTimeout(asked int, execCfg config.CommandConfig) int {
	if asked == 0 {
		asked = execCfg.TimeoutSec
	}
	return min(asked, execCfg.MaxTimeoutSec)
}

// redactor takes a redactor over the whole value set. Fresh each call because a
// Redactor carries per-stream state and counts, but the matcher it scans with
// is the store's, compiled once per load: building one here cost every command
// the size of the value set. The sudo grant adds nothing to it: an escalation
// is a decision rather than a value.
func (s *Server) redactor() *redact.Redactor {
	return s.Store.Redactor()
}

// safeDetail is an error message the agent may see, so it goes through the
// redactor: an unexpected error may have interpolated a value into it.
func (s *Server) safeDetail(detail string) string {
	return s.redactor().RedactText(detail)
}

// redactEach covers the command line an audit record carries. The broker never
// substitutes a value into argv, but a caller can, and this record goes to
// disk: what ran stays legible as "mysql -p«SECRET:db/root»".
func redactEach(r *redact.Redactor, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.RedactText(s)
	}
	return out
}

// CheckOutput is the operator-facing --check report: the refs refused at load,
// which the agent-facing status op never names, and the state of the configured
// SSH keys. Both exit non-zero, being a broker that serves without doing the
// job it was installed for.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	sshInfo, problems := s.describeSSH()
	escalationInfo, escalationProblems := s.describeEscalation()
	policy := s.policyProblems()
	body, err := json.MarshalIndent(map[string]any{
		"config":  s.Config.Path,
		"secrets": secrets, "ssh": sshInfo, "sudo": escalationInfo, "policy": policy,
	}, "", "  ")
	if err != nil {
		// Non-zero: a report that cannot be rendered is a broker nobody can
		// check.
		return []byte("the --check report could not be rendered: " + err.Error() + "\n"), 1
	}

	code := 0
	if len(policy) > 0 {
		for _, problem := range policy {
			log.Printf("socket policy: %s", problem)
		}
		code = 1
	}
	// A link that did not load: one ref refused, the broker still serving. Not
	// logged for the reason below, and non-zero so `doctor` and a converge run
	// see it rather than waiting for a command to ask for the ref.
	if degraded, _ := secrets["degraded_links"].(map[string]string); len(degraded) > 0 {
		code = 1
	}
	refused, _ := secrets["not_redactable"].(map[string]string)
	if len(refused) > 0 {
		// Nothing logged: loading already named every refused secret, and the JSON
		// body carries the same set as not_redactable.
		code = 1
	}
	// Reported and not counted. The daemon serves an empty value set, there
	// being no value for output to carry that the redactor lacks, so an operator
	// asking whether the host serves anything is told and a converge run is not
	// failed over a host that manages no credentials. What does fail is a
	// managed file that was found and did not load, below.
	if s.Store.Count() == 0 {
		log.Printf("the broker holds no managed values, so nothing is injectable " +
			"and nothing is redacted. Commands still run: there is nothing to " +
			"cover. A store on a filesystem that is not mounted looks the same " +
			"from here, so check that this host is meant to manage none")
	}
	if absent := s.Store.UnresolvedPatterns(); len(absent) > 0 {
		log.Printf("%d configured entry(ies) named no file: %v", len(absent), absent)
	}
	// A ref two managed files define differently. The loser is on disk and in no
	// redactor, so a command that prints it prints it in the clear: the same
	// consequence as a ref too short to cover, and counted the same way.
	if shadowed := s.Store.ShadowedRefs(); len(shadowed) > 0 {
		log.Printf("%d ref(s) are defined with different values by more than one "+
			"managed file; one value wins and the other is in no redactor: %v",
			len(shadowed), shadowed)
		code = 1
	}
	// Every value the broker failed to load is one it cannot redact.
	if fatal := s.Store.LoadErrors(); len(fatal) > 0 {
		log.Printf("%d secret load failure(s): %v", len(fatal), fatal)
		log.Printf("those values are absent from the redactor, so a command " +
			"that prints one prints it in plaintext")
		code = 1
	}
	if len(problems) > 0 {
		log.Printf("the broker cannot use the configured SSH key: %v", problems)
		log.Printf("brokered commands will reach no host that expects it; " +
			"place the key, or leave [ssh] key unset to authenticate some other way")
		code = 1
	}
	// Same weighting as the SSH key: an escalation that cannot be asked for
	// breaks only the commands that sudo, and those fail at the point of use with
	// sudo's own error.
	if len(escalationProblems) > 0 {
		log.Printf("this host cannot answer an escalation: %v", escalationProblems)
		log.Printf("a brokered command that runs sudo will fail to authenticate; " +
			"re-run `faramir init --allow-sudo`, or re-run without it to take the grant " +
			"away entirely")
		code = 1
	}
	// Not a warning: a host whose audit log cannot be written runs no brokered
	// command at all.
	if reason := s.Audit.Unwritable(); reason != "" {
		log.Printf("the audit log cannot be written: %s", reason)
		log.Printf("every brokered command is refused while that holds, a command " +
			"that cannot be recorded not being one this host runs")
		code = 1
	}
	return body, code
}

// describeEscalation reports whether this host could answer an escalation, and
// why not when it could not. Files rather than a live probe: putting the
// question would mean waiting on a human, and `--check` runs from `init`.
func (s *Server) describeEscalation() (map[string]any, []string) {
	info := map[string]any{"enabled": s.Escalation.Enabled()}
	if !s.Escalation.Enabled() {
		// The install that granted no sudoers entry, which is the default one.
		return info, nil
	}
	cfg := s.Config.Sudo
	info["exec_user"] = cfg.ExecUser
	info["pam_service"] = cfg.PamService
	info["helper"] = cfg.Helper
	info["notify_command"] = cfg.NotifyCommand

	var problems []string
	// The helper is what sudo's PAM service execs, as root. Absent, every
	// escalation fails closed.
	if _, err := os.Stat(cfg.Helper); err != nil {
		problems = append(problems, cfg.Helper+": "+err.Error()+
			" (the PAM service execs it, so no escalation can be approved)")
	}
	// The stack that execs it, wherever it is on this host: a service file of
	// faramir's own where sudo can be sent to one by name, and a block in the
	// stacks every account reads where it cannot. Absent either way, PAM falls
	// back to /etc/pam.d/other, which asks for a password nothing supplies on a
	// normal host and authenticates anything on one whose `other` is permissive;
	// doctor checks that too.
	if stack, err := escalation.Stack(escalation.PamDir, cfg.PamStack, cfg.PamService); err != nil {
		problems = append(problems, "nothing here authenticates an escalation: "+
			err.Error()+" (sudo would fall back to /etc/pam.d/other for "+
			cfg.ExecUser+")")
	} else {
		info["pam_stack"] = stack
	}
	// The notifier is optional, `faramir sudo watch` being where a
	// question is seen, but one configured and absent announces nothing,
	// silently.
	if len(cfg.NotifyCommand) > 0 {
		if _, err := osexec.LookPath(cfg.NotifyCommand[0]); err != nil {
			problems = append(problems, cfg.NotifyCommand[0]+": "+err.Error()+
				" ([sudo] notify_command names it, so nothing announces a pending request)")
		}
	}
	return info, problems
}

// policyProblems names the settings that widen what a socket admits. The
// keeper's socket is the age key by another route, and the executor's runs a
// command with no policy, redaction or audit record; each has exactly one
// legitimate client, this process. Identity by uid rather than name, the
// accounts being renamable at install time.
func (s *Server) policyProblems() []string {
	problems := []string{}
	// The socket itself, not a config key describing it: under systemd the
	// .socket unit's SocketMode= is what the mode ends up as. Unbound means
	// unchecked rather than passing.
	path := s.Config.Server.SocketPath
	if info, err := os.Stat(path); err != nil {
		log.Printf("%s is not bound, so its mode went unchecked: %v", path, err)
	} else if mode := info.Mode().Perm(); mode&0o007 != 0 {
		problems = append(problems, fmt.Sprintf(
			"%s is %04o: every account on this host can reach the broker, whatever "+
				"allowed_group says", path, mode))
	}
	if os.Geteuid() == 0 {
		log.Printf("running as root, so [keeper] and [executor] allowed_user were " +
			"not checked: run --check as the broker's own account")
		return problems
	}
	for _, socket := range []struct {
		section string
		account string
		cost    string
	}{
		{"keeper", s.Config.Keeper.AllowedUser,
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor", s.Config.Executor.AllowedUser,
			"a command sent there runs unredacted and unlogged"},
	} {
		// Unset is not checked: it fails loudly on its own, and what is looked for
		// here is a name admitting the wrong account.
		if socket.account != "" && !isSelf(socket.account) {
			problems = append(problems, fmt.Sprintf(
				"[%s] allowed_user names %s, which is not the broker: %s",
				socket.section, socket.account, socket.cost))
		}
	}
	return problems
}

// isSelf reports whether name resolves to the uid this process runs as.
func isSelf(name string) bool {
	entry, err := user.Lookup(name)
	if err != nil {
		return false
	}
	uid, err := strconv.Atoi(entry.Uid)
	return err == nil && uid == os.Geteuid()
}

// unusableReason names why ssh-add will refuse this key, or "" if it will take
// it: a passphrase-protected key, or [ssh] key pointing at the .pub. Either
// leaves the broker up with an agent holding nothing. The parse is what ssh-add
// would do, and its error carries no key material.
func unusableReason(data []byte) string {
	_, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		return ""
	}
	if _, ok := errors.AsType[*ssh.PassphraseMissingError](err); ok {
		return "passphrase-protected; the broker has no way to type one, " +
			"so ssh-add will refuse it"
	}
	if _, _, _, _, pubErr := ssh.ParseAuthorizedKey(data); pubErr == nil {
		return "this is a public key; [ssh] key must name the private key"
	}
	return "not a usable private key"
}

// describeSSH reports whether the broker can read and use the configured key,
// and why not when it cannot. A file check rather than a loaded-key count:
// --check runs before Ssh.Start, and starting a second agent would replace a
// running broker's socket.
func (s *Server) describeSSH() (map[string]any, []string) {
	info := map[string]any{"agent_socket": s.Config.Ssh.AgentSocket}
	path := s.Config.Ssh.Key
	// Absent is deliberate: the key then lives where the executor can read it.
	if path == "" {
		return info, nil
	}

	key := map[string]any{"path": path}
	info["key"] = key
	data, err := os.ReadFile(path)
	if err != nil {
		key["readable"] = false
		return info, []string{path + ": " + err.Error()}
	}
	key["readable"] = true
	if reason := unusableReason(data); reason != "" {
		key["usable"] = false
		key["reason"] = reason
		return info, []string{path + ": " + reason}
	}
	key["usable"] = true
	return info, nil
}
