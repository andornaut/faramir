// Package execserver runs brokered commands as faramir-exec, a uid that holds
// no secrets, audit log, age key or SSH keys.  A child forked by the broker
// would inherit all four.
//
// The PTY stays on the broker's side: it creates the pair, sends the slave over
// SCM_RIGHTS and keeps the master.  This service does the fork, the session
// setup and the reaping, and reports an exit status.
//
// Closing the connection means "give up", and kills the child's process group,
// which covers the broker dying mid-command.
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

// maxConcurrent is a backstop, not a knob.
//
// The broker is the executor's only permitted client and gates every child
// behind [server] max_concurrency, holding a slot for the whole run, so that
// number is the one that binds and this one is never reached. It was a config
// key set four times higher than the cap above it: an operator could raise or
// lower it and watch nothing change. What it still buys is that a broker with a
// bug cannot fork without limit here, which is a reason to keep the check and
// no reason to let anyone tune it.
const maxConcurrent = 16

func New(cfg *config.Config) *Executor {
	return &Executor{config: cfg, slots: make(chan struct{}, maxConcurrent)}
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
	delay := time.Duration(0)
	for {
		conn, err := e.ln.Accept()
		if err != nil {
			next, retry := sockutil.RetryAccept(err, delay)
			if !retry {
				e.wg.Wait()
				return nil
			}
			delay = next
			log.Printf("executor could not accept (%v); retrying in %v", err, delay)
			time.Sleep(delay)
			continue
		}
		delay = 0
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
	defer func() { _ = conn.Close() }()

	peer, err := sockutil.PeerCred(conn)
	if err != nil || !sockutil.AllowedUser(peer, e.config.Executor.AllowedUsers) {
		_ = sockutil.Send(conn, errorResponse("forbidden", "peer not authorized"))
		return
	}

	payload, slaveFD, err := readRequest(conn)
	// run takes ownership of slaveFD; any path that misses it must close the
	// descriptor here, or the broker's master never reaches EOF.
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
	defer func() { _ = uc.SetReadDeadline(time.Time{}) }()

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

	// Any fd past the first is a caller bug.
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
	// No fallback: the broker refuses a request that names no directory.
	cwd := req.Cwd
	if cwd == "" {
		return errorResponse("bad_request", "'cwd' must name the directory to run in")
	}

	// No allowlist: what bounds a brokered command is the uid it runs as.

	env := make([]string, 0, len(req.Env)+1)
	hasHome := false
	for k, v := range req.Env {
		if k == "HOME" {
			hasHome = true
		}
		env = append(env, k+"="+v)
	}
	// HOME belongs to this uid, not the broker's; ansible creates
	// ~/.ansible/tmp unconditionally.
	if !hasHome {
		env = append(env, "HOME="+ownHome())
	}

	timeoutSec := positive(req.TimeoutSec, e.config.Exec.DefaultTimeoutSec)
	graceSec := positive(req.KillGraceSec, e.config.Exec.KillGraceSec)

	// Nothing writes to the master, so a child reading stdin would block until
	// its timeout; /dev/null makes that an immediate EOF.  stdout and stderr
	// keep the PTY, which `test -t 1` and /dev/tty writes depend on.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return errorResponse("exec_failed", err.Error())
	}
	defer func() { _ = devnull.Close() }()

	cmd := exec.Command(req.Argv[0], req.Argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = devnull
	cmd.Stdout = slave
	cmd.Stderr = slave
	// Setsid makes the child a session leader, so killpg reaches everything it
	// spawns.  Ctty 1 is the slave, so a write to /dev/tty lands on our PTY.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true, Setctty: true, Ctty: 1}

	started := time.Now()
	if err := cmd.Start(); err != nil {
		return errorResponse("exec_failed", fmt.Sprintf("%s: %v", req.Argv[0], err))
	}
	// Our copy of the slave must go, or the master never reaches EOF.
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
// done is closed by the caller's cmd.Wait goroutine, since waiting twice would
// fail with ECHILD.
func (e *Executor) await(cmd *exec.Cmd, conn net.Conn, done <-chan struct{}, timeoutSec, graceSec int) bool {
	// A readable connection means the broker sent something or hung up; either
	// way it is no longer waiting, and the child must not outlive it.
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

// Client is one brokered command: start it, then collect its exit status.  Two
// calls, because the broker reads the PTY master in between.
type Client struct {
	socketPath string
	conn       *net.UnixConn
}

func NewClient(socketPath string) *Client { return &Client{socketPath: socketPath} }

func (c *Client) Start(argv []string, cwd string, env map[string]string,
	timeoutSec, killGraceSec int, slaveFD uintptr) error {
	addr, err := net.ResolveUnixAddr("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("executor socket %s: %v", c.socketPath, err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return fmt.Errorf("executor socket %s: %v", c.socketPath, err)
	}
	c.conn = conn

	line, err := json.Marshal(request{
		Argv: argv, Cwd: cwd, Env: env,
		TimeoutSec: timeoutSec, KillGraceSec: killGraceSec,
	})
	if err != nil {
		c.Close()
		return fmt.Errorf("executor: %v", err)
	}
	line = append(line, '\n')

	rights := unix.UnixRights(int(slaveFD))
	if _, _, err := conn.WriteMsgUnix(line, rights, nil); err != nil {
		c.Close()
		return fmt.Errorf("executor: %v", err)
	}
	return nil
}

// Abort hangs up.  The executor kills the child's process group.
func (c *Client) Abort() { c.Close() }

func (c *Client) Result(timeout time.Duration) (*ChildResult, error) {
	if c.conn == nil {
		return nil, fmt.Errorf("executor: no command in flight")
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
			return nil, fmt.Errorf("executor: %v", err)
		}
	}
	if idx := bytes.IndexByte(buf, '\n'); idx >= 0 {
		buf = buf[:idx]
	}
	if len(buf) == 0 {
		return nil, fmt.Errorf("executor closed the connection without responding")
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
		return nil, fmt.Errorf("malformed response from executor: %v", err)
	}
	if response.Error != nil {
		return nil, fmt.Errorf("%s: %s", response.Error.Code, response.Error.Message)
	}
	if response.ExitCode == nil {
		return nil, fmt.Errorf("executor response has no exit_code")
	}
	return &ChildResult{ExitCode: *response.ExitCode, TimedOut: response.TimedOut}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
