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
	osexec "os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/andornaut/faramir/internal/approval"
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
	Config   *config.Config
	Store    *secretstore.Store
	Audit    *audit.Log
	Ssh      *sshagent.Agent
	Approval *approval.Server

	// exec runs one command.  A field so a test can substitute one that records
	// what it was handed, rather than reaching broker policy through a socket, a
	// PTY and a forked process.
	exec func(*redact.Redactor, func(string), executor.Request) (*executor.Result, error)

	slots chan struct{}
	ln    net.Listener
	wg    sync.WaitGroup
}

func New(cfg *config.Config) *Server {
	s := &Server{
		Config:   cfg,
		Store:    secretstore.New(cfg.Secrets, cfg.Keeper),
		Audit:    audit.NewLog(cfg.Audit),
		Ssh:      sshagent.New(cfg.Ssh),
		Approval: approval.New(cfg.Sudo),
		slots:    make(chan struct{}, cfg.Server.MaxConcurrency),
		exec: func(r *redact.Redactor, sink func(string), req executor.Request) (*executor.Result, error) {
			return executor.Run(cfg.Exec, cfg.Executor, r, sink, req)
		},
	}
	// An approval is a thing that happened on this host, so it is recorded where
	// every other op is.  The record holds the command and the answer; the secret
	// is not in it, and could not be, the audit log being written after redaction
	// and that value being in the set.
	s.Approval.Record = func(entry map[string]any) { s.Audit.Write(entry, "") }
	return s
}

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
// to the client group; this also gives the audit log a real uid.
func (s *Server) peer(conn net.Conn) (*sockutil.Peer, error) {
	peer, err := sockutil.PeerCred(conn)
	if err != nil {
		log.Printf("SO_PEERCRED unavailable: %v", err)
		return nil, err
	}
	cfg := s.Config.Server
	if !sockutil.Allowed(peer, "", cfg.AllowedGroup) {
		return nil, nil
	}
	return peer, nil
}

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
	case "approvals":
		return s.opApprovals(request, peer)
	case "approve":
		return s.opApprove(request, peer)
	case "ask_approval":
		return s.opAskApproval(request, peer)
	default:
		return s.opExec(request, peer)
	}
}

func (s *Server) opStatus() protocol.Response {
	// Whether, not where.  Any member of the client group can ask, which includes
	// the coding agent, so what goes here lands in a model's context by default.
	// It is also the whole answer: a configured key that did not load looks
	// identical to a working one from the config's side, and that difference is
	// the only thing anyone debugs here.
	configured, usable := s.Config.Ssh.Key != "", false
	if configured {
		data, err := os.ReadFile(s.Config.Ssh.Key)
		usable = err == nil && unusableReason(data) == ""
	}
	body, _ := json.MarshalIndent(map[string]any{
		"version": version.Version,
		// Every file that contributed, in merge order.
		"configs": s.Config.Sources,
		"secrets": s.Store.Describe(),
		"ssh":     map[string]any{"configured": configured, "usable": usable},
		// Whether a brokered command may ask to sudo, which is worth the agent
		// knowing: without it a playbook that touches this host has to leave it out
		// and be applied some other way.  Whether, not how: the socket, the helper
		// and the password are none of a caller's business, and a human answers
		// every request either way.
		"sudo": map[string]any{"enabled": s.Approval.Enabled()},
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
// A deliberate oracle, and deliberately not rate-limited; docs/design.md has
// the weighting.  Only the input size and what was found are logged.
func (s *Server) opRedact(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.refuseUnreadable("redact", "a redact", audit.NewLogID()); refused != nil {
		return *refused
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

// opApprovals and opApprove are the operator's half of the approval channel,
// and with opAskApproval the only ops this socket refuses to a caller it
// otherwise admits.
//
// Root, checked with SO_PEERCRED, and nothing else: not the client group, which
// holds the account the coding agent runs as, and not the executor, which is the
// side asking.  This one check is what stands between an agent and its
// own approval, so it is made here rather than left to a file mode: the socket
// admits a group by design, and only the op knows that this request is
// different.
//
// An account that can reach root can already read the age key, so nothing is
// lost by trusting it here.
func (s *Server) requireRoot(op string, peer *sockutil.Peer) *protocol.Response {
	if peer != nil && peer.UID == 0 {
		return nil
	}
	out := protocol.ErrorResponse("forbidden", fmt.Sprintf(
		"%s is root's: an approval must be answered by an account the coding "+
			"agent cannot become. Run `sudo faramir approve`", op), "")
	return &out
}

// opAskApproval is what sudo's PAM helper asks, and the only thing that decides
// whether a brokered command becomes root.  It blocks until a human answers.
//
// Root, like the other two: the helper reaches it because pam_exec runs it with
// seteuid inside sudo, and the child that holds the token cannot spend it.  That
// is what makes the token an identifier rather than a credential.  There is no
// credential anywhere in this, which is why sudo is answered rather than
// authenticated.
func (s *Server) opAskApproval(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("ask_approval", peer); refused != nil {
		return *refused
	}
	if request.Token == "" {
		return protocol.ErrorResponse("bad_request",
			"'token' must name the brokered command asking to sudo", "")
	}
	approved, reason := s.Approval.Ask(request.Token)
	// A refusal is a response rather than an error: the helper reports it to PAM
	// as a failed authentication, which is what sudo has to see.
	return protocol.Response{
		"exit_code": 0, "approved": approved, "reason": reason,
		"output": reason + "\n", "truncated": false,
		"redactions": []any{}, "log_id": nil,
	}
}

func (s *Server) opApprovals(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("approvals", peer); refused != nil {
		return *refused
	}
	wait := min(time.Duration(request.WaitSec)*time.Second, maxApprovalWait)
	questions := s.Approval.QuestionsWait(wait)
	body, _ := json.MarshalIndent(map[string]any{"questions": questions}, "", "  ")
	return protocol.Response{
		"exit_code": 0, "output": string(body) + "\n", "questions": questions,
		"truncated": false, "redactions": []any{}, "log_id": nil,
	}
}

func (s *Server) opApprove(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	if refused := s.requireRoot("approve", peer); refused != nil {
		return *refused
	}
	// Named by the answering account rather than by uid alone: the audit record is
	// read by a person asking who let something through.
	who := fmt.Sprintf("uid %d", peer.UID)
	if entry, err := user.LookupId(strconv.Itoa(int(peer.UID))); err == nil {
		who = entry.Username
	}
	if peer.PID > 0 {
		who = fmt.Sprintf("%s (pid %d)", who, peer.PID)
	}
	if err := s.Approval.Answer(request.ID, request.Approve, who); err != nil {
		return protocol.ErrorResponse("unknown_question", err.Error(), "")
	}
	verdict := "refused"
	if request.Approve {
		verdict = "approved"
	}
	return protocol.Response{
		"exit_code": 0, "output": request.ID + " " + verdict + "\n",
		"truncated": false, "redactions": []any{}, "log_id": nil,
	}
}

// maxApprovalWait bounds a watcher's long poll.  It returns an empty list and
// the watcher asks again, so a broker restarted under it is noticed rather than
// waited on forever.
const maxApprovalWait = 60 * time.Second

func (s *Server) opListSecrets() protocol.Response {
	// Names only, and only refs that loaded: a value the redactor cannot cover is
	// refused at load.
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

// secretsDir is where a first file goes, taken from the configured pattern
// rather than a default: --config-dir moves it, and naming the wrong directory
// in the one actionable line here would send the operator somewhere the broker
// does not read.
func (s *Server) secretsDir() string {
	if patterns := s.Config.Secrets.Files; len(patterns) > 0 {
		return filepath.Dir(patterns[0])
	}
	return "the directory [secrets] files names"
}

// refuseUnreadable is the gate on the two ops whose output is redacted against
// the value set.  One question for both, because both risk the same thing: see
// Store.Unreadable.
//
// Here rather than at startup, for two reasons.  A check at startup judges the
// host as it was at boot, so a reload that shrinks the set afterwards passes
// unremarked; and exiting takes the daemon down just when `faramir status` and
// `doctor` are what would explain why.  status and list_secrets stay available
// for the second reason: neither produces output that depends on the set.
func (s *Server) refuseUnreadable(op, phrase, logID string) *protocol.Response {
	reason := s.Store.Unreadable()
	if reason == "" {
		return nil
	}
	log.Printf("%s refusing %s: %s", logID, phrase, reason)
	// Recorded like a served call.  A refusal is what the operator is looking for
	// when they ask why nothing ran, and the audit log is where every other op
	// answers that.
	s.Audit.Write(map[string]any{
		"log_id": logID, "op": op, "refused": "no_secrets", "reason": reason,
	}, "")
	out := protocol.ErrorResponse("no_secrets", fmt.Sprintf(
		"the broker does not hold every managed value, so %s would run with "+
			"redaction covering less than the config asks for: %s. Encrypt a first "+
			"file into %s with sops, or `sudo faramir edit` once one is there, then "+
			"retry", phrase, reason, s.secretsDir()), logID)
	return &out
}

func (s *Server) opExec(request *protocol.Request, peer *sockutil.Peer) protocol.Response {
	execCfg := s.Config.Exec
	logID := audit.NewLogID()
	if refused := s.refuseUnreadable("exec", "this command", logID); refused != nil {
		return *refused
	}

	cmd, envRefs := request.Cmd, request.EnvRefs

	// No fallback: a brokered command runs where its caller was, and nothing else
	// knows where that is.
	cwd := request.Cwd
	if !request.HasCwd || cwd == "" {
		return protocol.ErrorResponse("bad_request",
			"no cwd: name the directory to run in.", logID)
	}
	// Fails early with a clear message; it enforces nothing.  Permission is left
	// to the executor, whose uid may hold traversal the broker does not. Absence
	// is refused here, being knowable from any uid.
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

	// The only place plaintext is touched outside the store, and it goes straight
	// into the child's environ.  HOME is left to the executor.
	env := make(map[string]string, len(execCfg.BaseEnv)+1)
	maps.Copy(env, execCfg.BaseEnv)
	// SSH_AUTH_SOCK: the child can authenticate with the keys, not read them.
	maps.Copy(env, s.Ssh.Env())
	// A token, and nothing else: the child can be identified when it asks to
	// sudo, and a human answers out of band.  Not a capability: spending it is an
	// op the broker refuses to anything but root, so what the child holds names its
	// run rather than authorising it.
	//
	// Registered before the child starts and dropped when it ends, so a request
	// that arrives late is refused rather than answered against a finished
	// command.  The argv is the redacted one, this reaching a terminal and the log.
	token, held := s.Approval.Register(approval.Run{
		Argv: redactEach(s.redactor(), cmd), Cwd: cwd, LogID: logID,
	})
	// Held while another command holds an approval: the two share the
	// executor's uid, so running this one now would give it a route to the root
	// that was approved for the other.  Busy rather than an error: the caller
	// retries, and the wait is bounded by the approved run's own life.
	if held {
		return protocol.ErrorResponse("busy", "an approval is running as "+
			"the executor's uid; no other brokered command runs until it ends, so "+
			"nothing can ride its approval. Retry shortly", logID)
	}
	defer s.Approval.Release(token)
	maps.Copy(env, s.Approval.Env(token))
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

	// Every known secret, not only the injected ones: a managed host can print one
	// the broker never injected.
	redactor := s.redactor()
	collector := audit.NewCollector(s.Config.Audit.MaxRecordBytes)
	started := time.Now()

	result, err := s.exec(redactor, collector.Add, executor.Request{
		Argv:       append([]string{argv0Path}, cmd[1:]...),
		Cwd:        cwd,
		Env:        env,
		TimeoutSec: timeout,
	})
	// Drop the plaintext as soon as the child has it; the store keeps the values.
	for k := range env {
		delete(env, k)
	}
	if err != nil {
		detail := s.safeDetail(err.Error())
		// The child ran as the executor whatever failed afterwards, so it is
		// recorded before the error is returned: without this a command that
		// reached a managed host leaves nothing behind but a daemon-log line.
		record := s.redactor()
		s.Audit.Write(map[string]any{
			"log_id": logID, "op": "exec", "peer": peer,
			"cmd":        redactEach(record, cmd),
			"argv0_path": record.RedactText(argv0Path),
			"cwd":        record.RedactText(cwd),
			"env_refs":   injected,
			"started_at": started.Unix(),
			"error":      detail,
		}, collector.Text())
		return protocol.ErrorResponse("exec_failed", detail, logID)
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
//
// The sudo grant adds nothing here, which is the point of it: an approval is a
// decision rather than a value, so there is no credential for a child to print
// back and none for this to cover.
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
// SSH keys.  Both are non-zero, being a broker that serves without doing the
// job it was installed for.
func (s *Server) CheckOutput() ([]byte, int) {
	secrets := s.Store.DescribeForOperator()
	sshInfo, problems := s.describeSSH()
	approvalInfo, approvalProblems := s.describeApproval()
	policy := s.policyProblems()
	body, _ := json.MarshalIndent(map[string]any{
		"configs": s.Config.Sources,
		"secrets": secrets, "ssh": sshInfo, "sudo": approvalInfo, "policy": policy,
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
		// Nothing logged: loading already named every refused secret, and the JSON
		// body carries the same set as not_redactable.
		code = 1
	}
	// The audit is stricter than the daemon's own gate, which is the split: the
	// daemon starts while the secrets directory is not written yet, and refuses
	// exec and redact until it is.  Here that state fails, because a host serving
	// nothing is one an operator asked about and should be told about.
	if s.Store.Count() == 0 {
		log.Printf("the broker holds no managed values, so nothing is injectable " +
			"and nothing is redacted; exec and redact are refused until one loads")
		code = 1
	}
	if absent := s.Store.Unresolved(); len(absent) > 0 {
		log.Printf("%d configured entry(ies) named no file: %v", len(absent), absent)
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
		log.Printf("the broker cannot use the configured SSH key: %v", problems)
		log.Printf("brokered commands will reach no host that expects it; " +
			"place the key, or leave [ssh] key unset to authenticate some other way")
		code = 1
	}
	// Same weighting as the SSH key: an approval that cannot be asked for breaks
	// only the commands that sudo, and those fail at the point of use with
	// sudo's own error.  Here is where an operator finds out without waiting for a
	// playbook to.
	if len(approvalProblems) > 0 {
		log.Printf("this host cannot answer an approval: %v", approvalProblems)
		log.Printf("a brokered command that runs sudo will fail to authenticate; " +
			"re-run `faramir init --allow-sudo`, or re-run without it to take the grant " +
			"away entirely")
		code = 1
	}
	return body, code
}

// describeApproval reports whether this host could answer an approval, and
// why not when it could not.  Files rather than a live probe: putting the
// question would mean waiting on a human, and `--check` runs from `init`.
func (s *Server) describeApproval() (map[string]any, []string) {
	info := map[string]any{"enabled": s.Approval.Enabled()}
	if !s.Approval.Enabled() {
		// The install that granted no sudoers entry, which is the default one.
		return info, nil
	}
	cfg := s.Config.Sudo
	info["exec_user"] = cfg.ExecUser
	info["pam_service"] = cfg.PamService
	info["helper"] = cfg.Helper
	info["notify_command"] = cfg.NotifyCommand

	var problems []string
	// The helper is what sudo's PAM service execs, as root.  Absent, every
	// approval fails closed, which is safe and useless.
	if _, err := os.Stat(cfg.Helper); err != nil {
		problems = append(problems, cfg.Helper+": "+err.Error()+
			" (the PAM service execs it, so no approval can be approved)")
	}
	// The PAM service file itself.  Absent, PAM falls back to /etc/pam.d/other,
	// which on a normal host asks for a password nothing supplies, but on one whose
	// `other` is permissive would authenticate anything, so doctor checks that too.
	pamFile := "/etc/pam.d/" + cfg.PamService
	if _, err := os.Stat(pamFile); err != nil {
		problems = append(problems, pamFile+": "+err.Error()+
			" (sudo would fall back to /etc/pam.d/other for "+cfg.ExecUser+")")
	}
	// The notifier is optional, `faramir approve --watch` being where a question is
	// seen, but one that is configured and absent announces nothing, silently.
	if len(cfg.NotifyCommand) > 0 {
		if _, err := osexec.LookPath(cfg.NotifyCommand[0]); err != nil {
			problems = append(problems, cfg.NotifyCommand[0]+": "+err.Error()+
				" ([sudo] notify_command names it, so nothing announces a pending request)")
		}
	}
	return info, problems
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
	// The socket itself, not a config key describing it: under systemd the .socket
	// unit's SocketMode= is what the mode ends up as, so a key here could read
	// 0660 while the bound socket is world-writable.  Unbound means unchecked
	// rather than passing.
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
		// Unset is not checked: it fails loudly on its own, and the failure looked
		// for here is a name admitting the wrong account.
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
// it.  In practice: a passphrase-protected key, or [ssh] key pointing at the
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
		return "this is a public key; [ssh] key must name the private key"
	}
	return "not a usable private key"
}

// describeSSH reports whether the broker can read and use the configured key,
// and why not when it cannot.  A file check rather than a loaded-key count:
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
