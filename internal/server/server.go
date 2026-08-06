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
	"os/user"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

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
)

// Version is the reported build version.
const Version = "0.1.0-go"

type Server struct {
	Config *config.Config
	Store  *secretstore.Store
	Audit  *audit.Log
	Ssh    *sshagent.Agent

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
	for {
		conn, err := s.ln.Accept()
		if err != nil {
			s.wg.Wait()
			return nil
		}
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

// Reload re-fetches the value set.  Wired to SIGHUP.
func (s *Server) Reload() {
	log.Printf("SIGHUP: reloading secrets")
	s.Store.Reload()
}

func (s *Server) serveConnection(conn net.Conn) {
	defer conn.Close()

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
// The socket mode already restricts this to the devwork group; this is belt
// and braces, and it gives the audit log a real uid.
func (s *Server) peer(conn net.Conn) (*sockutil.Peer, error) {
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		return nil, err
	}
	cfg := s.Config.Server
	allowed := peer.UID == 0 || int(peer.UID) == os.Getuid()
	if !allowed && len(cfg.AllowedUIDs) > 0 {
		for _, uid := range cfg.AllowedUIDs {
			if int32(uid) == peer.UID {
				allowed = true
				break
			}
		}
	}
	if !allowed && len(cfg.AllowedGroups) > 0 {
		name := ""
		if u, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
			name = u.Username
		}
		for _, group := range cfg.AllowedGroups {
			g, err := user.LookupGroup(group)
			if err != nil {
				continue
			}
			if gid, err := strconv.Atoi(g.Gid); err == nil && int32(gid) == peer.GID {
				allowed = true
				break
			}
			if name != "" {
				if members, err := groupMembers(group); err == nil {
					for _, m := range members {
						if m == name {
							allowed = true
							break
						}
					}
				}
			}
			if allowed {
				break
			}
		}
	}
	if !allowed {
		log.Printf("rejected connection from uid=%d gid=%d pid=%d", peer.UID, peer.GID, peer.PID)
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
	default:
		return s.opExec(request, peer)
	}
}

func (s *Server) opStatus() protocol.Response {
	body, _ := json.MarshalIndent(map[string]any{
		"version":     Version,
		"config":      s.Config.Path,
		"secrets":     s.Store.Describe(),
		"default_cwd": s.Config.Exec.DefaultCwd,
	}, "", "  ")
	return protocol.Response{
		"exit_code": 0, "output": string(body) + "\n",
		"truncated": false, "redactions": []any{}, "log_id": nil,
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

	cmd, envRefs, err := protocol.ResolveInlineTokens(request.Cmd, request.EnvRefs)
	if err != nil {
		return protocol.ErrorResponse("bad_request", err.Error(), logID)
	}

	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		cwd = execCfg.DefaultCwd
	}
	if info, err := os.Stat(cwd); err != nil || !info.IsDir() {
		return protocol.ErrorResponse("bad_request", "cwd does not exist: "+cwd, logID)
	}

	argv0Path, err := resolve.Program(cmd[0], cwd, execCfg)
	if err != nil {
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": "exec", "peer": peer,
			"cmd": cmd, "cwd": cwd, "error": err.Error(),
		}, "")
		return protocol.ErrorResponse("exec_failed", err.Error(), logID)
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
	collector := audit.NewRawCollector(s.Config.Audit.MaxRecordBytes)
	started := time.Now()

	argv := append([]string{argv0Path}, cmd[1:]...)
	result, err := executor.Run(argv, cwd, env, timeout, redactor, execCfg,
		s.Config.Executor, collector.Add)
	// Drop the plaintext from this map as soon as the child has it.  The
	// values live on in the store, which is where they belong; a stale copy
	// here would outlive the request for no reason.
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		return protocol.ErrorResponse("exec_failed", s.safeDetail(err.Error()), logID)
	}

	s.Audit.Write(map[string]any{
		"log_id": logID, "op": "exec", "peer": peer, "cmd": cmd,
		"argv0_path": argv0Path, "cwd": cwd, "env_refs": injected, "exit_code": result.ExitCode,
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

// safeDetail is an error message the agent may see.
//
// An unexpected error can have interpolated a secret into its message, so it
// goes through the redactor like every other agent-visible string.
func (s *Server) safeDetail(detail string) string {
	return redact.New(s.Store.Pairs(), s.Store.Policy).RedactText(detail)
}

// CheckOutput is the operator-facing --check report.  It names the refs that
// were refused at load, which the agent-facing status op never does.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	body, _ := json.MarshalIndent(map[string]any{"secrets": secrets}, "", "  ")

	refused, _ := secrets["not_redactable"].(map[string]string)
	if len(refused) > 0 {
		keys := make([]string, 0, len(refused))
		for k := range refused {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		log.Printf("%d secret(s) refused as not redactable: %v", len(keys), keys)
		// Non-zero on a refused ref: the config parses, but a command that
		// injects that ref will fail at runtime, and --check is the install
		// gate that is supposed to catch it.
		return body, 1
	}
	return body, 0
}

// groupMembers reads the supplementary member list for a group.  Go's os/user
// exposes no equivalent of grp.getgrnam().gr_mem.
func groupMembers(name string) ([]string, error) {
	data, err := os.ReadFile("/etc/group")
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Split(line, ":")
		if len(fields) >= 4 && fields[0] == name {
			return strings.Split(fields[3], ","), nil
		}
	}
	return nil, nil
}
