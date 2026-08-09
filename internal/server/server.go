// Package server is the broker daemon.  Socket-activated by systemd
// (LISTEN_FDS), falling back to binding the socket itself when run standalone.
// Requests over [server] max_concurrency are refused rather than queued.
package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"maps"
	"net"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
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

	// exec runs one command.  A field so a test can substitute one that records
	// what it was handed, rather than reaching broker policy through a socket, a
	// PTY and a forked process.
	exec func(*redact.Redactor, func(string), executor.Request) (*executor.Result, error)

	slots chan struct{}
	ln    net.Listener
	wg    sync.WaitGroup

	// redacts counts the redact op per calling uid over a sliding minute.
	redacts struct {
		sync.Mutex
		at map[int32][]time.Time
	}
}

// allowRedact reports whether this peer may run one more redact, and records
// it.  A sliding window rather than a token bucket, which would let a burst
// through after a quiet spell.  Keyed by uid, since each request is its own
// connection.
func (s *Server) allowRedact(peer *sockutil.Peer) bool {
	limit := s.Config.Server.MaxRedactsPerMin
	if limit <= 0 || peer == nil {
		return true
	}
	now := time.Now()
	cutoff := now.Add(-time.Minute)

	s.redacts.Lock()
	defer s.redacts.Unlock()
	if s.redacts.at == nil {
		s.redacts.at = map[int32][]time.Time{}
	}
	kept := s.redacts.at[peer.UID][:0]
	for _, at := range s.redacts.at[peer.UID] {
		if at.After(cutoff) {
			kept = append(kept, at)
		}
	}
	if len(kept) >= limit {
		s.redacts.at[peer.UID] = kept
		return false
	}
	s.redacts.at[peer.UID] = append(kept, now)
	return true
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

// peer performs the SO_PEERCRED check.  The socket mode already restricts this
// to the dev group; this also gives the audit log a real uid.
func (s *Server) peer(conn net.Conn) (*sockutil.Peer, error) {
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		return nil, err
	}
	cfg := s.Config.Server
	if !sockutil.Allowed(peer, nil, cfg.AllowedGroups) {
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
		// Every file that contributed, in merge order.
		"configs": s.Config.Sources,
		"secrets": s.Store.Describe(),
	}, "", "  ")
	return protocol.Response{
		"exit_code": 0, "output": string(body) + "\n",
		"truncated": false, "redactions": []any{}, "log_id": nil,
	}
}

// opRedact scrubs text the caller already holds, so a session outside the
// broker's uid gets the same redaction a brokered command does.  The value set
// never leaves this process.
//
// It is a deliberate oracle, bounded by [server] max_redacts_per_min and
// recorded like every other op; see docs/design.md.  Only the input size and
// what was found are logged, never the text.
func (s *Server) opRedact(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	// Refused rather than delayed: a wait would stall the agent's shell with no
	// explanation.
	if !s.allowRedact(peer) {
		logID := audit.NewLogID()
		log.Printf("%s uid %d is over [server] max_redacts_per_min (%d); refusing",
			logID, peer.UID, s.Config.Server.MaxRedactsPerMin)
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": "redact", "peer": peer,
			"input_bytes": len(request.Text), "refused": "rate_limited",
		}, "")
		return protocol.ErrorResponse("rate_limited", fmt.Sprintf(
			"more than %d redact calls in a minute from this account; "+
				"raise [server] max_redacts_per_min if this is ordinary use",
			s.Config.Server.MaxRedactsPerMin), logID)
	}
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
	// Names only, and only refs that loaded: a value the redactor cannot cover
	// is refused at load.
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

	// No fallback: a brokered command runs where its caller was, and nothing
	// else knows where that is.
	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		return protocol.ErrorResponse("bad_request",
			"no cwd: name the directory to run in.", logID)
	}
	// Fails early with a clear message; it enforces nothing.  Permission is left
	// to the executor, whose uid may hold traversal the broker does not.
	// Absence is refused here, being knowable from any uid.
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
		// Redacted like every other agent-visible string.
		record := s.redactor()
		detail := record.RedactText(err.Error())
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": "exec", "peer": peer,
			"cmd": redactEach(record, cmd), "cwd": record.RedactText(cwd),
			"error": detail,
		}, "")
		return protocol.ErrorResponse("exec_failed", detail, logID)
	}

	// The only place plaintext is touched outside the store, and it goes
	// straight into the child's environ.  HOME is left to the executor.
	env := make(map[string]string, len(execCfg.BaseEnv)+1)
	maps.Copy(env, execCfg.BaseEnv)
	// SSH_AUTH_SOCK: the child can authenticate with the keys, not read them.
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

	// Every known secret, not only the injected ones: a managed host can print
	// one the broker never injected.
	redactor := redact.New(s.Store.Pairs(), s.Store.Policy)
	collector := audit.NewCollector(s.Config.Audit.MaxRecordBytes)
	started := time.Now()

	result, err := s.exec(redactor, collector.Add, executor.Request{
		Argv:       append([]string{argv0Path}, cmd[1:]...),
		Cwd:        cwd,
		Env:        env,
		TimeoutSec: timeout,
	})
	// Drop the plaintext as soon as the child has it; the store keeps the
	// values.
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
// Redactor carries per-stream state and counts.
func (s *Server) redactor() *redact.Redactor {
	return redact.New(s.Store.Pairs(), s.Store.Policy)
}

// safeDetail is an error message the agent may see, so it goes through the
// redactor: an unexpected error may have interpolated a value into it.
func (s *Server) safeDetail(detail string) string {
	return s.redactor().RedactText(detail)
}

// redactEach covers the command line an audit record carries.  The broker never
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
// SSH keys.  Both are non-zero, being a broker that serves without doing the job
// it was installed for.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	sshInfo, problems := s.describeSSH()
	policy := s.policyProblems()
	body, _ := json.MarshalIndent(map[string]any{
		"configs": s.Config.Sources,
		"secrets": secrets, "ssh": sshInfo, "policy": policy,
	}, "", "  ")

	code := 0
	if len(policy) > 0 {
		for _, problem := range policy {
			log.Printf("socket policy: %s", problem)
		}
		code = 1
	}
	refused, _ := secrets["not_redactable"].(map[string]string)
	if len(refused) > 0 {
		// Nothing logged: loading already named every refused secret, and the
		// JSON body carries the same set as not_redactable.
		code = 1
	}
	// Every value the broker failed to load is one it cannot redact.  Absent
	// counts: an unmounted store is indistinguishable from one never written.
	if fatal := s.Store.LoadErrors(); len(fatal) > 0 {
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

// policyProblems names the settings that widen what a socket admits.  The
// keeper's socket is the age key by another route, and the executor's runs a
// command with no policy, redaction or audit record; each has exactly one
// legitimate client, this process.
//
// Identity by uid rather than name, since the accounts can be renamed at
// install time.  From root every name compares unequal, so those checks are
// reported as unchecked instead.
func (s *Server) policyProblems() []string {
	problems := []string{}
	if mode := s.Config.Server.SocketMode; mode&0o007 != 0 {
		problems = append(problems, fmt.Sprintf(
			"[server] socket_mode is %04o: every account on this host can reach the "+
				"broker, whatever allowed_groups says", mode))
	}
	if os.Geteuid() == 0 {
		log.Printf("running as root, so [keeper] and [executor] allowed_users were " +
			"not checked: run --check as the broker's own account")
		return problems
	}
	for _, socket := range []struct {
		section string
		users   []string
		cost    string
	}{
		{"keeper", s.Config.Keeper.AllowedUsers,
			"asking it for a decrypted value is the age key without reading the file"},
		{"executor", s.Config.Executor.AllowedUsers,
			"a command sent there runs unredacted and unlogged"},
	} {
		// An empty list is not checked: it fails loudly on its own, and the
		// failure looked for here is a list admitting one account too many.
		for _, name := range socket.users {
			if !isSelf(name) {
				problems = append(problems, fmt.Sprintf(
					"[%s] allowed_users names %s, which is not the broker: %s",
					socket.section, name, socket.cost))
			}
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
// it.  In practice: a passphrase-protected key, or [ssh] keys pointing at the
// .pub.  Either leaves the broker up with an agent holding nothing.  The parse
// is what ssh-add would do, and its error carries no key material.
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

// describeSSH reports which configured keys the broker can read and use, and
// one line per key that is neither.  A file check rather than a loaded-key
// count: --check runs before Ssh.Start, and starting a second agent would
// replace a running broker's socket.
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
		// Empty is deliberate: the keys then live where the executor can read
		// them.
		"keys": keys,
	}, problems
}
