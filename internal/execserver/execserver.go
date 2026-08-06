// Package execserver runs brokered commands as a uid that holds nothing.
//
// The broker resolves policy, injects secret values, redacts output and writes
// the audit log.  It does not fork the child: this service does, under
// faramir-exec, which holds no secrets, cannot read the raw log, cannot read
// the age key, and cannot read the SSH keys that reach managed hosts.
//
// The split is what makes those statements true.  A child forked by the broker
// shares the broker's uid, and anything that uid can read or write, the child
// can read or write.
//
// The PTY stays on the broker's side.  The broker creates the pair, sends the
// slave over SCM_RIGHTS, and keeps the master, so redaction, truncation and
// the audit log run exactly where they always did and the output never makes
// an extra hop.  This service does the fork, the session setup and the
// reaping, and reports an exit status.
//
// Closing the connection is how the broker says "give up": the child's process
// group is killed.  That covers the broker dying mid-command, which would
// otherwise leave an orphan holding a credential in its environment.
package execserver

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sockutil"
)

const maxRequestBytes = 1 << 20

// Error means the executor refused the request, or could not be reached.
type Error struct{ Msg string }

func (e *Error) Error() string { return e.Msg }

func errf(format string, args ...any) error { return &Error{Msg: fmt.Sprintf(format, args...)} }

type request struct {
	Argv         []string          `json:"argv"`
	Cwd          string            `json:"cwd"`
	Env          map[string]string `json:"env"`
	TimeoutSec   int               `json:"timeout_sec"`
	KillGraceSec int               `json:"kill_grace_sec"`
}

// --------------------------------------------------------------------------
// Server
// --------------------------------------------------------------------------

type Executor struct {
	config *config.Config
	ln     net.Listener
	slots  chan struct{}
	wg     sync.WaitGroup
}

func New(cfg *config.Config) *Executor {
	return &Executor{config: cfg, slots: make(chan struct{}, cfg.Executor.MaxConcurrency)}
}

func (e *Executor) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(e.config.Executor.SocketPath, e.config.Executor.SocketMode)
	if err != nil {
		return nil, err
	}
	e.ln = ln
	return ln, nil
}

func (e *Executor) Serve() error {
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			e.wg.Wait()
			return nil
		}
		e.wg.Add(1)
		go func() {
			defer e.wg.Done()
			e.serveConnection(conn)
		}()
	}
}

func (e *Executor) Close() error {
	if e.ln != nil {
		return e.ln.Close()
	}
	return nil
}

func (e *Executor) serveConnection(conn net.Conn) {
	defer conn.Close()

	peer, err := sockutil.PeerCred(conn)
	if err != nil || !sockutil.AllowedByUsersOrGroups(peer,
		e.config.Executor.AllowedUsers, e.config.Executor.AllowedGroups) {
		_ = sockutil.Send(conn, errorResponse("forbidden", "peer not authorized"))
		return
	}

	payload, slaveFD, err := readRequest(conn)
	// run takes ownership of slaveFD; every path that does not reach it has to
	// close the descriptor here or the broker's master never reaches EOF.
	if err != nil || payload == nil {
		if slaveFD >= 0 {
			_ = unix.Close(slaveFD)
		}
		_ = sockutil.Send(conn, errorResponse("bad_request", "no usable request"))
		return
	}
	if slaveFD < 0 {
		_ = sockutil.Send(conn, errorResponse("bad_request", "no terminal fd was passed"))
		return
	}

	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		_ = unix.Close(slaveFD)
		_ = sockutil.Send(conn, errorResponse("busy", "executor is at its concurrency limit"))
		return
	}

	_ = sockutil.Send(conn, e.run(payload, slaveFD, conn))
}

// readRequest reads one JSON line and the single fd that accompanies it.
func readRequest(conn net.Conn) (*request, int, error) {
	uc, ok := conn.(*net.UnixConn)
	if !ok {
		return nil, -1, errors.New("not a unix connection")
	}
	_ = uc.SetReadDeadline(time.Now().Add(30 * time.Second))
	defer uc.SetReadDeadline(time.Time{})

	buf := make([]byte, 0, 4096)
	chunk := make([]byte, 65536)
	oob := make([]byte, unix.CmsgSpace(4))
	fds := []int{}

	for {
		if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
			break
		}
		n, oobn, _, _, err := uc.ReadMsgUnix(chunk, oob)
		if oobn > 0 {
			if scms, perr := unix.ParseSocketControlMessage(oob[:oobn]); perr == nil {
				for _, scm := range scms {
					if got, perr := unix.ParseUnixRights(&scm); perr == nil {
						fds = append(fds, got...)
					}
				}
			}
		}
		if n > 0 {
			buf = append(buf, chunk[:n]...)
			if len(buf) > maxRequestBytes {
				break
			}
		}
		if err != nil {
			break
		}
	}

	// Any fd past the first is a caller bug; close them rather than leak.
	for _, extra := range fds[min(1, len(fds)):] {
		_ = unix.Close(extra)
	}
	slaveFD := -1
	if len(fds) > 0 {
		slaveFD = fds[0]
	}

	if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
		buf = buf[:idx]
	}
	if len(buf) == 0 {
		return nil, slaveFD, nil
	}
	var req request
	if err := json.Unmarshal(buf, &req); err != nil {
		return nil, slaveFD, err
	}
	return &req, slaveFD, nil
}

// run takes ownership of slaveFD and always closes it.
func (e *Executor) run(req *request, slaveFD int, conn net.Conn) map[string]any {
	slave := os.NewFile(uintptr(slaveFD), "pty-slave")
	slaveOpen := true
	closeSlave := func() {
		if slaveOpen {
			slaveOpen = false
			_ = slave.Close()
		}
	}
	defer closeSlave()

	if len(req.Argv) == 0 {
		return errorResponse("bad_request", "'argv' must be a non-empty list of strings")
	}
	cwd := req.Cwd
	if cwd == "" {
		cwd = e.config.Exec.DefaultCwd
	}

	// There is no allowlist to re-check here any more.  What bounds a brokered
	// command is the uid it runs as, which holds no key, no audit log and no
	// SSH key, not a list of permitted programs.

	env := make([]string, 0, len(req.Env)+1)
	hasHome := false
	for k, v := range req.Env {
		if k == "HOME" {
			hasHome = true
		}
		env = append(env, k+"="+v)
	}
	// The child's HOME belongs to this uid, not the broker's.  Ansible creates
	// ~/.ansible/tmp unconditionally and fails if it cannot.
	if !hasHome {
		env = append(env, "HOME="+ownHome())
	}

	timeoutSec := positive(req.TimeoutSec, e.config.Exec.DefaultTimeoutSec)
	graceSec := positive(req.KillGraceSec, e.config.Exec.KillGraceSec)

	// Nothing ever writes to the master, so a child reading stdin would block
	// until its timeout, holding a concurrency slot: bash with no arguments,
	// or any password prompt, does it.  /dev/null turns that into an immediate
	// EOF.  stdout and stderr keep the PTY, which is what `test -t 1` and
	// writes to /dev/tty depend on.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return errorResponse("exec_failed", err.Error())
	}
	defer devnull.Close()

	cmd := exec.Command(req.Argv[0], req.Argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = devnull
	cmd.Stdout = slave
	cmd.Stderr = slave
	// Setsid makes the child a session leader, so its pid is its process-group
	// id and killpg reaches everything it spawns.  Ctty 1 is the slave, which
	// is how a write to /dev/tty (ssh and sudo prompts) lands on our PTY.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 1}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return errorResponse("exec_failed", fmt.Sprintf("%s: %v", req.Argv[0], err))
	}
	// The broker holds the master; our copy of the slave must go now, or the
	// master never reaches EOF and the broker waits forever.
	closeSlave()

	waitDone := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(waitDone)
	}()
	timedOut := e.await(cmd, conn, waitDone, timeoutSec, graceSec)
	<-waitDone

	exitCode := cmd.ProcessState.ExitCode()
	if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok && status.Signaled() {
		exitCode = 128 + int(status.Signal())
	}
	duration := time.Since(started).Seconds()
	suffix := ""
	if timedOut {
		suffix = " (timed out)"
	}
	log.Printf("%s exit=%d dur=%.1fs%s", filepath.Base(req.Argv[0]), exitCode, duration, suffix)

	return map[string]any{
		"exit_code":    exitCode,
		"timed_out":    timedOut,
		"duration_sec": round3(duration),
	}
}

// await waits for the child, watching the clock and the broker's connection.
// done is closed by the caller's cmd.Wait goroutine; waiting twice on the same
// process would make one of the two calls fail with ECHILD.
func (e *Executor) await(cmd *exec.Cmd, conn net.Conn, done <-chan struct{}, timeoutSec, graceSec int) bool {
	// A readable connection means the broker sent something (it should not) or
	// hung up.  Either way it is no longer waiting for us, and an orphan
	// holding a credential in its environment is exactly what must not survive.
	hangup := make(chan struct{})
	go func() {
		one := make([]byte, 1)
		for {
			n, err := conn.Read(one)
			if err != nil {
				close(hangup)
				return
			}
			if n == 0 {
				close(hangup)
				return
			}
			// Unexpected data; keep going.
		}
	}()

	timer := time.NewTimer(time.Duration(timeoutSec) * time.Second)
	defer timer.Stop()

	select {
	case <-done:
		return false
	case <-timer.C:
		log.Printf("pid %d exceeded %ds; killing", cmd.Process.Pid, timeoutSec)
		terminate(cmd, graceSec)
		return true
	case <-hangup:
		log.Printf("broker hung up; killing pid %d", cmd.Process.Pid)
		terminate(cmd, graceSec)
		return false
	}
}

// terminate SIGTERMs the whole process group, then SIGKILLs what is left.
func terminate(cmd *exec.Cmd, graceSec int) {
	pid := cmd.Process.Pid
	for _, sig := range []syscall.Signal{syscall.SIGTERM, syscall.SIGKILL} {
		if err := syscall.Kill(-pid, sig); err != nil {
			_ = cmd.Process.Signal(sig)
		}
		wait := time.Duration(graceSec) * time.Second
		if sig == syscall.SIGKILL {
			wait = 5 * time.Second
		}
		deadline := time.Now().Add(wait)
		for time.Now().Before(deadline) {
			if err := syscall.Kill(pid, 0); err != nil {
				return // gone
			}
			time.Sleep(20 * time.Millisecond)
		}
		log.Printf("pid %d survived %v", pid, sig)
	}
}

func ownHome() string {
	if u, err := user.Current(); err == nil && u.HomeDir != "" {
		return u.HomeDir
	}
	return "/tmp"
}

func positive(value, fallback int) int {
	if value > 0 {
		return value
	}
	return fallback
}

func round3(v float64) float64 {
	return float64(int64(v*1000+0.5)) / 1000
}

func errorResponse(code, message string) map[string]any {
	return map[string]any{"error": map[string]string{"code": code, "message": message}}
}

// --------------------------------------------------------------------------
// Client (used by the broker)
// --------------------------------------------------------------------------

type ChildResult struct {
	ExitCode int
	TimedOut bool
}

// Client is one brokered command: start it, then collect its exit status.
//
// The broker keeps the PTY master and reads it between Start and Result, so
// this cannot be a single blocking call.
type Client struct {
	socketPath string
	conn       *net.UnixConn
}

func NewClient(socketPath string) *Client { return &Client{socketPath: socketPath} }

func (c *Client) Start(argv []string, cwd string, env map[string]string,
	timeoutSec, killGraceSec int, slaveFD uintptr) error {
	addr, err := net.ResolveUnixAddr("unix", c.socketPath)
	if err != nil {
		return errf("executor socket %s: %v", c.socketPath, err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return errf("executor socket %s: %v", c.socketPath, err)
	}
	c.conn = conn

	line, err := json.Marshal(request{
		Argv: argv, Cwd: cwd, Env: env,
		TimeoutSec: timeoutSec, KillGraceSec: killGraceSec,
	})
	if err != nil {
		c.Close()
		return errf("executor: %v", err)
	}
	line = append(line, '\n')

	rights := unix.UnixRights(int(slaveFD))
	if _, _, err := conn.WriteMsgUnix(line, rights, nil); err != nil {
		c.Close()
		return errf("executor: %v", err)
	}
	return nil
}

// Abort hangs up.  The executor kills the child's process group.
func (c *Client) Abort() { c.Close() }

func (c *Client) Result(timeout time.Duration) (*ChildResult, error) {
	if c.conn == nil {
		return nil, errf("executor: no command in flight")
	}
	defer c.Close()
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))

	buf := make([]byte, 0, 1024)
	chunk := make([]byte, 65536)
	for bytes.IndexByte(buf, '\n') < 0 {
		n, err := c.conn.Read(chunk)
		if n > 0 {
			buf = append(buf, chunk[:n]...)
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, errf("executor: %v", err)
		}
	}
	if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
		buf = buf[:idx]
	}
	if len(buf) == 0 {
		return nil, errf("executor closed the connection without responding")
	}

	var response struct {
		ExitCode *int `json:"exit_code"`
		TimedOut bool `json:"timed_out"`
		Error    *struct {
			Code    string `json:"code"`
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(buf, &response); err != nil {
		return nil, errf("malformed response from executor: %v", err)
	}
	if response.Error != nil {
		return nil, errf("%s: %s", response.Error.Code, response.Error.Message)
	}
	if response.ExitCode == nil {
		return nil, errf("executor response has no exit_code")
	}
	return &ChildResult{ExitCode: *response.ExitCode, TimedOut: response.TimedOut}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
