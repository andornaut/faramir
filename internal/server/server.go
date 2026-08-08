// Package server is the broker daemon.
//
// Socket-activated by systemd (LISTEN_FDS); falls back to binding the socket
// itself when run standalone, which is how the test harness drives it.
//
// Concurrency is bounded ([server] max_concurrency) because each brokered
// command may be a full Ansible run.  Requests over the limit are refused with
// a clear error rather than queued indefinitely.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/executor"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/redact"
	"github.com/andornaut/faramir/internal/resolve"
	"github.com/andornaut/faramir/internal/secretref"
	"github.com/andornaut/faramir/internal/secretstore"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/sshagent"
	"github.com/andornaut/faramir/internal/version"
)

type Server struct {
	Config *config.Config
	Store  *secretstore.Store
	Audit  *audit.Log
	Ssh    *sshagent.Agent

	// exec runs one command.  A field rather than a direct call to
	// executor.Run because everything opExec decides around the child -- the
	// timeout it settles on, the environment it assembles, the record it
	// writes, the concurrency limit it enforces -- is broker policy, and
	// reaching it through a socket, a PTY and a forked process tests the
	// plumbing instead.  New wires in the real executor; a test substitutes
	// one that records what it was handed.
	exec func(*redact.Redactor, func(string), executor.Request) (*executor.Result, error)

	slots chan struct{}
	ln    net.Listener
	wg    sync.WaitGroup
}

func New(cfg *config.Config) *Server {
	return &Server{
		Config: cfg,
		Store:  secretstore.New(cfg.Secrets, cfg.Keeper),
		Audit:  audit.NewLog(cfg.Audit),
		Ssh:    sshagent.New(cfg.Ssh),
		slots:  make(chan struct{}, cfg.Server.MaxConcurrency),
		exec: func(r *redact.Redactor, sink func(string), req executor.Request) (*executor.Result, error) {
			return executor.Run(cfg.Exec, cfg.Executor, r, sink, req)
		},
	}
}

func (s *Server) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(s.Config.Server.SocketPath, s.Config.Server.SocketMode)
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
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConnection(conn)
		}()
	}
}

func (s *Server) Close() error {
	if s.ln != nil {
		return s.ln.Close()
	}
	return nil
}

func (s *Server) serveConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	peer, err := s.peer(conn)
	if err != nil || peer == nil {
		_ = sockutil.Send(conn, protocol.ErrorResponse("forbidden", "peer not authorized", ""))
		return
	}

	_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	line, err := sockutil.ReadLine(conn, s.Config.Server.MaxRequestBytes)
	if err != nil {
		if errors.Is(err, sockutil.ErrTooLarge) {
			_ = sockutil.Send(conn, protocol.ErrorResponse("too_large",
				fmt.Sprintf("request exceeds %d bytes", s.Config.Server.MaxRequestBytes), ""))
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
	_ = conn.SetReadDeadline(time.Time{})

	var payload map[string]any
	if err := json.Unmarshal(line, &payload); err != nil {
		_ = sockutil.Send(conn, protocol.ErrorResponse("bad_request",
			fmt.Sprintf("invalid JSON: %v", err), ""))
		return
	}
	_ = sockutil.Send(conn, s.Handle(payload, peer))
}

// peer performs the SO_PEERCRED check.
//
// The socket mode already restricts this to the dev group; this is belt
// and braces, and it gives the audit log a real uid.
func (s *Server) peer(conn net.Conn) (*sockutil.Peer, error) {
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		return nil, err
	}
	cfg := s.Config.Server
	if !sockutil.Allowed(peer, cfg.AllowedUIDs, nil, cfg.AllowedGroups) {
		return nil, nil
	}
	return peer, nil
}

// --------------------------------------------------------------------------
// Dispatch
// --------------------------------------------------------------------------

func (s *Server) Handle(payload map[string]any, peer *sockutil.Peer) protocol.Response {
	request, err := protocol.Parse(payload)
	if err != nil {
		return protocol.ErrorResponse("bad_request", err.Error(), "")
	}

	s.Store.RefreshIfStale()

	switch request.Op {
	case "status":
		return s.opStatus()
	case "list_secrets":
		return s.opListSecrets()
	case "redact":
		return s.opRedact(request, peer)
	default:
		return s.opExec(request, peer)
	}
}

func (s *Server) opStatus() protocol.Response {
	body, _ := json.MarshalIndent(map[string]any{
		"version": version.Version,
		"config":  s.Config.Path,
		// Every file that contributed, not just the base: a setting that is not
		// what an operator expects is usually a drop-in they forgot applies.
		"config_sources": s.Config.Sources,
		"secrets":        s.Store.Describe(),
	}, "", "  ")
	return protocol.Response{
		"exit_code": 0, "output": string(body) + "\n",
		"truncated": false, "redactions": []any{}, "log_id": nil,
	}
}

// opRedact scrubs text the caller already holds.
//
// The value set never leaves this process: the caller sends text and gets it
// back with every value replaced by its token, which is what lets a session
// running outside the broker's uid have the same redaction a brokered command
// gets.  Without it the redactor covers only what the broker itself ran, and
// everything an agent reads or executes directly is uncovered.
//
// It is an oracle, deliberately: a caller can ask about a guessed value and the
// answer says whether the guess was right.  That is a trade this design accepts
// -- see docs/scope.md -- because the failure it exists to stop is a credential
// reaching the transcript by accident, and an accident does not guess.
// Recorded like every other op, because it is the one an oracle attack would
// use: a caller probing a guessed value leaves a run of redact calls that hit
// nothing, and without a record there is no trace of it at all.  The text is
// not logged, only its size and what was found in it, so the record still holds
// no value and neither confirms nor denies a guess to anyone reading the log.
func (s *Server) opRedact(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	redactor := s.redactor()
	output := redactor.RedactText(request.Text)
	summary := redactor.Summary()
	logID := audit.NewLogID()
	s.Audit.Write(map[string]any{
		"log_id": logID, "op": "redact", "peer": peer,
		"input_bytes": len(request.Text), "redactions": summary,
	}, "")
	return protocol.Response{
		"exit_code": 0, "output": output, "truncated": false,
		"redactions": summary, "log_id": logID,
	}
}

func (s *Server) opListSecrets() protocol.Response {
	// Names only, and only refs that were actually loaded: a value the redactor
	// cannot cover is refused at load and never listed here.
	refs := s.Store.Refs()
	var output strings.Builder
	for _, ref := range refs {
		output.WriteString("secret://" + ref + "\n")
	}
	return protocol.Response{
		"exit_code": 0, "output": output.String(),
		"truncated": false, "redactions": []any{}, "log_id": nil, "refs": refs,
	}
}

func (s *Server) opExec(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	execCfg := s.Config.Exec
	logID := audit.NewLogID()

	cmd, envRefs := request.Cmd, request.EnvRefs

	// No fallback anywhere: a brokered command runs where its caller was, and
	// nothing else knows where that is.  Every shipped caller sends its own
	// directory, so a request without one is a client that did not.
	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		return protocol.ErrorResponse("bad_request",
			"no cwd: name the directory to run in.", logID)
	}
	// This stat fails early with a clear message; it enforces nothing.  The uid
	// that enters the directory is the executor's, and it can hold traversal the
	// broker does not: an ecryptfs home discards an ACL written through the
	// mount, so one can end up granting the executor and not the broker.
	// Refusing on the broker's own EACCES would make that arrangement unusable
	// for a directory the executor can enter perfectly well.
	//
	// So permission is left to the executor, which reports its own failure if it
	// cannot get there either.  Absence is still refused here, being knowable
	// from any uid, and worth catching before a child is forked to discover it.
	info, statErr := os.Stat(cwd)
	switch {
	case statErr == nil && !info.IsDir():
		return protocol.ErrorResponse("bad_request", "cwd is not a directory: "+cwd, logID)
	case os.IsPermission(statErr):
		// The executor decides.
	case statErr != nil:
		return protocol.ErrorResponse("bad_request", "cwd does not exist: "+cwd, logID)
	}

	argv0Path, err := resolve.Program(cmd[0], cwd, execCfg)
	if err != nil {
		// Redacted like every other agent-visible string, and like the output
		// this log records: "the audit log holds no value" is worth more as a
		// property with no exceptions than as one with a footnote.
		record := s.redactor()
		detail := record.RedactText(err.Error())
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": "exec", "peer": peer,
			"cmd": redactEach(record, cmd), "cwd": record.RedactText(cwd),
			"error": detail,
		}, "")
		return protocol.ErrorResponse("exec_failed", detail, logID)
	}

	// Resolve secret values.  This is the only place plaintext is touched
	// outside the store, and it goes straight into the child's environ.  The
	// age key is not among them: the keeper holds it, and nothing the broker
	// executes can obtain it.
	// HOME is left to the executor: the child runs as its uid, not ours.
	env := make(map[string]string, len(execCfg.BaseEnv)+1)
	maps.Copy(env, execCfg.BaseEnv)
	// SSH_AUTH_SOCK, when the broker holds the keys in an agent.  The child can
	// authenticate with them; it cannot read them.
	maps.Copy(env, s.Ssh.Env())
	injected := map[string]string{}
	for name, uri := range envRefs {
		ref, err := secretref.Parse(uri)
		if err != nil {
			return protocol.ErrorResponse("unknown_secret", err.Error(), logID)
		}
		value, err := s.Store.Value(ref)
		if err != nil {
			return protocol.ErrorResponse("unknown_secret", err.Error(), logID)
		}
		env[name] = value
		injected[name] = ref
	}

	timeout := request.TimeoutSec
	if timeout == 0 {
		timeout = execCfg.DefaultTimeoutSec
	}
	if timeout > execCfg.MaxTimeoutSec {
		timeout = execCfg.MaxTimeoutSec
	}

	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		return protocol.ErrorResponse("busy", fmt.Sprintf(
			"broker is at its concurrency limit (%d); retry shortly",
			s.Config.Server.MaxConcurrency), logID)
	}

	// The value set is every known secret, not only the injected ones: a
	// managed host can print a credential the broker never injected, and
	// catching that is the accidental-disclosure guarantee.
	redactor := redact.New(s.Store.Pairs(), s.Store.Policy)
	collector := audit.NewCollector(s.Config.Audit.MaxRecordBytes)
	started := time.Now()

	result, err := s.exec(redactor, collector.Add, executor.Request{
		Argv:       append([]string{argv0Path}, cmd[1:]...),
		Cwd:        cwd,
		Env:        env,
		TimeoutSec: timeout,
	})
	// Drop the plaintext from this map as soon as the child has it.  The
	// values live on in the store, which is where they belong; a stale copy
	// here would outlive the request for no reason.
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		return protocol.ErrorResponse("exec_failed", s.safeDetail(err.Error()), logID)
	}

	record := s.redactor()
	s.Audit.Write(map[string]any{
		"log_id": logID, "op": "exec", "peer": peer,
		"cmd":        redactEach(record, cmd),
		"argv0_path": record.RedactText(argv0Path),
		"cwd":        record.RedactText(cwd),
		"env_refs":   injected, "exit_code": result.ExitCode,
		"duration_sec": result.DurationSec, "timed_out": result.TimedOut,
		"started_at": started.Unix(), "redactions": result.Redactions,
	}, collector.Text())

	total := 0
	for _, r := range result.Redactions {
		total += r.Count
	}
	log.Printf("%s %s exit=%d dur=%.1fs redactions=%d",
		logID, filepath.Base(argv0Path), result.ExitCode, result.DurationSec, total)

	return protocol.Response{
		"exit_code": result.ExitCode, "output": result.Output,
		"truncated": result.Truncated, "redactions": result.Redactions,
		"log_id": logID, "timed_out": result.TimedOut,
		"duration_sec": result.DurationSec,
	}
}

// redactor builds a fresh matcher over the whole value set.  Fresh because a
// Redactor carries per-stream state and per-stream counts; the one the child's
// output goes through must not be shared with anything else.
func (s *Server) redactor() *redact.Redactor {
	return redact.New(s.Store.Pairs(), s.Store.Policy)
}

// safeDetail is an error message the agent may see.
//
// An unexpected error can have interpolated a secret into its message, so it
// goes through the redactor like every other agent-visible string.
func (s *Server) safeDetail(detail string) string {
	return s.redactor().RedactText(detail)
}

// redactEach covers the command line an audit record carries.
//
// The broker never substitutes a value into argv, which is why a value cannot
// reach ps or /proc/<pid>/cmdline through it.  A caller can still put one there
// itself, and unlike argv this record is written to disk, so it gets the same
// treatment as the output: what ran stays legible as
// "mysql -p«SECRET:db/root»", and the value does not land in the file.
func redactEach(r *redact.Redactor, in []string) []string {
	out := make([]string, len(in))
	for i, s := range in {
		out[i] = r.RedactText(s)
	}
	return out
}

// CheckOutput is the operator-facing --check report.  It names the refs that
// were refused at load, which the agent-facing status op never does, and the
// state of the SSH keys the broker is configured to lend.
//
// Both are the same shape of problem: a broker that starts, serves, and cannot
// do the job it was installed for.  --check is the install gate, so both are
// reported and both are non-zero.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	sshInfo, problems := s.describeSSH()
	body, _ := json.MarshalIndent(map[string]any{
		"config_sources": s.Config.Sources,
		"secrets":        secrets, "ssh": sshInfo,
	}, "", "  ")

	code := 0
	refused, _ := secrets["not_redactable"].(map[string]string)
	if len(refused) > 0 {
		// Nothing logged here.  Loading the values already named every refused
		// secret and said why, and repeating it is most of what makes this
		// failure a wall of text once ansible has wrapped it.  The JSON body
		// below carries the same set as not_redactable.
		//
		// Non-zero on a refused ref: the config parses, but a command that
		// injects that ref will fail at runtime, and --check is the install
		// gate that is supposed to catch it.
		code = 1
	}
	// A configured file that does not exist yet is the not-yet-migrated state
	// and stays quiet.  A file that exists and did not load, or a keeper that
	// did not answer, leaves the broker serving fewer values than it is
	// configured for, and every value it is missing is one it cannot redact.
	if fatal := s.Store.FatalLoadErrors(); len(fatal) > 0 {
		log.Printf("%d secret load failure(s): %v", len(fatal), fatal)
		log.Printf("those values are absent from the redactor, so a command " +
			"that prints one prints it in plaintext")
		code = 1
	}
	if len(problems) > 0 {
		log.Printf("%d configured SSH key(s) the broker cannot use: %v", len(problems), problems)
		log.Printf("brokered commands will reach no host that expects one; " +
			"place the key, or set [ssh] keys = [] to authenticate some other way")
		code = 1
	}
	return body, code
}

// unusableReason names why ssh-add will refuse this key, or "" if it will take
// it.  The two cases that happen in practice are a key with a passphrase
// (nothing is there to type one) and [ssh] keys pointing at the .pub by
// mistake.  Both leave the broker up with an agent holding nothing, so every
// brokered command fails to authenticate against the entire fleet while every
// socket is active and every unit is running.
//
// The parse is what ssh-add itself would do, rather than a guess from the file
// name, and its error is reported without any of the key material in it.
func unusableReason(data []byte) string {
	_, err := ssh.ParseRawPrivateKey(data)
	if err == nil {
		return ""
	}
	var needsPassphrase *ssh.PassphraseMissingError
	if errors.As(err, &needsPassphrase) {
		return "passphrase-protected; the broker has no way to type one, " +
			"so ssh-add will refuse it"
	}
	if _, _, _, _, pubErr := ssh.ParseAuthorizedKey(data); pubErr == nil {
		return "this is a public key; [ssh] keys must name the private key"
	}
	return "not a usable private key"
}

// describeSSH reports which of the configured keys the broker can actually
// read and use, and returns one line per key that is neither.
//
// The agent is not started here, so this is the file check rather than the
// loaded-key count: --check runs before Ssh.Start, and starting a second agent
// would replace a running broker's socket.  A key that is present and readable
// is the part an install can get wrong; ssh-add failing on a passphrase is
// visible in the journal at startup.
func (s *Server) describeSSH() (map[string]any, []string) {
	keys := make([]map[string]any, 0, len(s.Config.Ssh.Keys))
	var problems []string
	for _, path := range s.Config.Ssh.Keys {
		data, err := os.ReadFile(path)
		readable := err == nil
		entry := map[string]any{"path": path, "readable": readable}
		if !readable {
			problems = append(problems, path+": "+err.Error())
			keys = append(keys, entry)
			continue
		}
		if reason := unusableReason(data); reason != "" {
			entry["usable"] = false
			entry["reason"] = reason
			problems = append(problems, path+": "+reason)
		} else {
			entry["usable"] = true
		}
		keys = append(keys, entry)
	}
	return map[string]any{
		"agent_socket": s.Config.Ssh.AgentSocket,
		// Empty is a deliberate configuration, not a fault: the keys then live
		// where the executor's own uid can read them.
		"keys": keys,
	}, problems
}
