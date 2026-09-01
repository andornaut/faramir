// Package broker is the broker daemon. Socket-activated by systemd
// (LISTEN_FDS), falling back to binding the socket itself when run standalone.
// Requests over [command] concurrency are refused rather than queued.
package broker

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"sync"
	"time"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/escalation"
	"github.com/andornaut/faramir/internal/execclient"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/secretstore"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/sshagent"
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
	exec func(*redact.Redactor, func(string), execclient.Request) (*execclient.Result, error)

	slots chan struct{}
	ln    net.Listener
	wg    sync.WaitGroup

	// Every connection still being served, so Close can unblock the ones parked
	// on a peer. See Close.
	connsMu sync.Mutex
	conns   map[net.Conn]struct{}
	closing bool
}

// New builds the broker over one config.
//
// ownDirs is what this install occupies, from the caller rather than worked
// out here: where the install put itself is the installer's to know, and a
// daemon that derived it would be a second answer to drift from.
//
// The rules about faramir's own commands and files are not a parameter. They
// are the same on every host, denyrules holds them, and a caller that had to
// pass them was a caller that could pass none: that is how the commands acting
// on the install came to be refused to a shell and allowed to a brokered
// command.
func New(ownDirs []string, cfg *config.Config) *Server {
	s := &Server{
		Config: cfg,
		// What this host declares, as the rules a brokered command is held to.
		// Compiled once: the entries change by `faramir block add` and `faramir
		// link add`, each of which rewrites the config and restarts what reads it.
		// The whole catalogue, in the order denyrules holds it: first match wins
		// here as it does in the guard's rendered file, and taking the order from
		// one place is what keeps the two from answering the same command
		// differently.
		declared: newDeclaredCheck(
			denyrules.Catalogue(agentHomeDir(cfg.Server.AgentUser), ownDirs, cfg.Ssh.Key, cfg.Secret)),
		Store:      secretstore.New(cfg.Secret, cfg.Keeper),
		Audit:      audit.NewLog(cfg.Audit),
		Ssh:        sshagent.New(cfg.Ssh),
		Escalation: escalation.New(cfg.Sudo),
		slots:      make(chan struct{}, cfg.Command.Concurrency),
		exec: func(r *redact.Redactor, sink func(string), req execclient.Request) (*execclient.Result, error) {
			return execclient.Run(cfg.Command, cfg.Executor, r, sink, req)
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
