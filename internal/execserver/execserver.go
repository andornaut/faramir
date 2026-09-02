// Package execserver runs brokered commands as faramir-exec, a uid that holds
// no secrets, audit log, age key or SSH keys. A child forked by the broker
// would inherit all four.
//
// The PTY stays on the broker's side: it creates the pair, sends the slave over
// SCM_RIGHTS and keeps the master. This service does the fork, the session
// setup and the reaping, and reports an exit status.
//
// Closing the connection cancels the run and tears down its cgroup, which covers
// the broker dying mid-command.
package execserver

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"strconv"
	"sync"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

const maxRequestBytes = 1 << 20

type request struct {
	// Op names anything that is not "start a command", which is what an absent op
	// means.
	Op string `json:"op"`
	// Version is what the broker's binary reports. The daemons are one binary
	// under three units, so a difference is one of them left running across the
	// install that replaced it, and every request it sends is refused.
	Version string   `json:"version"`
	Argv    []string `json:"argv"`
	Cwd     string   `json:"cwd"`
	// Stdin is what the caller piped into the brokered command, base64 in this
	// request as it was in the broker's. Empty leaves the child on /dev/null,
	// which is what a command with nothing to read gets.
	Stdin        []byte            `json:"stdin,omitempty"`
	Env          map[string]string `json:"env"`
	TimeoutSec   int               `json:"timeout_sec"`
	KillGraceSec int               `json:"kill_grace_sec"`
	// RunID is what the broker calls this run, so an escalation raised inside it
	// can be attributed back to the command a human was shown. Empty where the
	// host grants no escalation, which leaves the run unattributable and so
	// unable to sudo.
	RunID string `json:"run_id"`
	// Procs is what an owner question asks about: the pids the PAM helper walked,
	// most recent first.
	Procs []int `json:"procs"`
}

// opQuiescent asks whether any process of this uid is alive outside the runs
// this executor is confining. The broker cannot answer it: its own unit sets
// ProtectProc=invisible, so another uid's /proc is not in its view. This
// service shares the uid with every brokered command.
const (
	// opExec starts a command, which is what an absent op means.
	opExec      = "exec"
	opQuiescent = "quiescent"
	// opOwner names the run that forked one of a list of processes. The broker
	// cannot answer it either: only this service knows what it forked, and it is
	// what lets a sudo be attributed to a command a human approved.
	opOwner = "owner"
)

type Executor struct {
	config *config.Config
	ln     net.Listener
	slots  chan struct{}
	wg     sync.WaitGroup
	// cgroupBase is the cgroup v2 directory each run is confined under, or ""
	// where no delegated cgroup is available. Set once at New. Confinement is
	// the one reaper, so "" means every command is refused until the host is
	// fixed.
	cgroupBase string

	// live is the run cgroups in flight, which the quiescence answer measures
	// against: a process of this uid is accounted for if it is this daemon or a
	// member of one of these.
	liveMu sync.Mutex
	live   map[*runCgroup]struct{}

	// owned is what each in-flight run was forked as, keyed by the id the broker
	// gave it. An escalation is attributed by comparing this against the ancestry
	// the PAM helper walked: the broker holds what a run is, this holds what it
	// forked, and neither takes the asking process's word for either.
	//
	// Recorded after the fork, because that is when the pid exists, and dropped
	// with the run: a request naming a process no live run owns is refused.
	ownedMu sync.Mutex
	owned   map[string]ownedRun
}

// maxConcurrent is a backstop, not a knob: the broker is this socket's only
// permitted client and holds a [command] concurrency slot for the whole of each
// run, so that number binds first. This one bounds a broker with a bug.
//
// The same constant the loader holds [command] concurrency to, so "binds first"
// is enforced rather than assumed.
const maxConcurrent = config.MaxConcurrentRuns

func New(cfg *config.Config) *Executor {
	e := &Executor{
		config: cfg,
		slots:  make(chan struct{}, maxConcurrent),
		live:   map[*runCgroup]struct{}{},
		owned:  map[string]ownedRun{},
	}
	// Probed once: per run this is a field read rather than a syscall.
	e.cgroupBase = cgroupBase()
	if e.cgroupBase == "" {
		log.Printf("this executor has no delegated cgroup, so brokered commands will be " +
			"refused: it needs cgroup v2, a unit that sets Delegate=, and a kernel with " +
			"cgroup.kill (>= 5.14). Reinstall on such a host")
	}
	return e
}

func (e *Executor) Listen() (net.Listener, error) {
	ln, err := sockutil.Listen(e.config.Executor.SocketPath)
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
		e.wg.Go(func() {
			e.serveConnection(conn)
		})
	}
}

func (e *Executor) serveConnection(conn net.Conn) {
	defer func() { _ = conn.Close() }()

	peer, err := sockutil.PeerCred(conn)
	if err != nil || !sockutil.AllowedUser(peer, e.config.Executor.AllowedUser) {
		_ = sockutil.Send(conn, sockutil.ErrorResponse("forbidden", "peer not authorized"))
		return
	}

	payload, slaveFD, err := readRequest(conn)
	// run takes ownership of slaveFD; every other return leaves it to this
	// close, or the broker's master never reaches EOF.
	adopted := false
	defer func() {
		if !adopted && slaveFD >= 0 {
			_ = unix.Close(slaveFD)
		}
	}()
	if err != nil || payload == nil {
		_ = sockutil.Send(conn, sockutil.ErrorResponse("bad_request", "no usable request"))
		return
	}
	// Before the op and the terminal-fd check both: a caller of another release
	// is refused whatever it asked for, and told that rather than told about
	// whichever field changed under it.
	if why := version.Mismatch(payload.Version); why != "" {
		_ = sockutil.Send(conn, sockutil.ErrorResponse("bad_request", why))
		return
	}
	// Before the terminal-fd check: a question about the host carries no PTY. An
	// unknown op is named rather than fed to run(), which would report it as a
	// malformed command.
	switch payload.Op {
	case "", opExec:
	case opQuiescent:
		_ = sockutil.Send(conn, e.quiescence())
		return
	case opOwner:
		_ = sockutil.Send(conn, e.ownerOf(payload.Procs))
		return
	default:
		_ = sockutil.Send(conn, sockutil.ErrorResponse("bad_request",
			"unknown op "+strconv.Quote(payload.Op)))
		return
	}
	if slaveFD < 0 {
		_ = sockutil.Send(conn, sockutil.ErrorResponse("bad_request", "no terminal fd was passed"))
		return
	}

	select {
	case e.slots <- struct{}{}:
		defer func() { <-e.slots }()
	default:
		_ = sockutil.Send(conn, sockutil.ErrorResponse("busy", "executor is at its concurrency limit"))
		return
	}

	adopted = true
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
		return sockutil.ErrorResponse("bad_request", "'argv' must be a non-empty list of strings")
	}
	// No fallback: the broker refuses a request that names no directory.
	cwd := req.Cwd
	if cwd == "" {
		return sockutil.ErrorResponse("bad_request", "'cwd' must name the directory to run in")
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
	// HOME belongs to this uid, not the broker's; ansible creates ~/.ansible/tmp
	// unconditionally.
	if !hasHome {
		env = append(env, "HOME="+ownHome())
	}

	timeoutSec := positive(req.TimeoutSec, e.config.Command.TimeoutSec)
	graceSec := positive(req.KillGraceSec, config.KillGraceSec)

	// Nothing writes to the master, so a child reading stdin would block until its
	// timeout; /dev/null makes that an immediate EOF. stdout and stderr keep the
	// PTY, which `test -t 1` depends on.
	devnull, err := os.Open(os.DevNull)
	if err != nil {
		return sockutil.ErrorResponse("exec_failed", err.Error())
	}
	defer func() { _ = devnull.Close() }()

	// What the caller piped in, if anything, on a pipe of its own: the bytes are
	// already here and bounded, so they are written and the write end closed,
	// which is the EOF /dev/null was standing in for. A pipe rather than the PTY,
	// which is what keeps a credential prompt unanswerable: nothing here can
	// open /dev/tty, and this feeds the program's stdin alone.
	childStdin := devnull
	if len(req.Stdin) > 0 {
		reader, writer, pipeErr := os.Pipe()
		if pipeErr != nil {
			return sockutil.ErrorResponse("exec_failed", pipeErr.Error())
		}
		defer func() { _ = reader.Close() }()
		go func() {
			defer func() { _ = writer.Close() }()
			// A child that exits without reading its input leaves this write to
			// fail with EPIPE, which is the child's choice rather than a fault.
			_, _ = writer.Write(req.Stdin)
		}()
		childStdin = reader
	}

	cmd := exec.CommandContext(context.Background(), req.Argv[0], req.Argv[1:]...)
	cmd.Dir = cwd
	cmd.Env = env
	cmd.Stdin = childStdin
	cmd.Stdout = slave
	cmd.Stderr = slave
	// Setsid and no controlling terminal. A child that has one can open /dev/tty,
	// which is what every credential prompt reads so a pipe cannot answer it:
	// ssh-add, sudo, gpg. Nothing writes to the master, so that read would block
	// until the timeout; without a controlling terminal the open fails and the
	// program falls back to stdin, which is /dev/null unless the caller piped
	// something in. A prompt reading that gets the caller's first line and not a
	// passphrase anybody typed, which is the caller's own doing and not a way for
	// one to be asked for.
	//
	// What it gives up is the text of a prompt from a program that writes only to
	// /dev/tty and has no fallback: that write fails, so it reaches neither the
	// operator nor the record. A program with a fallback prints to stderr, which
	// is on the PTY and is redacted and recorded like the rest.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	// A handle on the process about to be forked, taken by the fork itself and so
	// before the exec that can hide it: what an escalation raised inside this run
	// is attributed by. -1 where the kernel has no CLONE_PIDFD, which own() reports
	// and refuses to attribute anything to.
	pidfd := -1
	cmd.SysProcAttr.PidFD = &pidfd

	// Confine the run to its own cgroup, the one reaper: a descendant that calls
	// setsid, which a process-group kill would miss, is still reaped when the
	// cgroup is torn down. A host with no delegated cgroup, or a run that cannot
	// be given one, is refused rather than reaped by process group.
	if e.cgroupBase == "" {
		return sockutil.ErrorResponse("exec_failed", "this host has no delegated cgroup (needs "+
			"cgroup v2, a unit with Delegate=, and a kernel with cgroup.kill >= 5.14); "+
			"refusing to run a command it cannot confine and reap")
	}
	rcg, err := newRunCgroup(e.cgroupBase)
	if err != nil {
		return sockutil.ErrorResponse("exec_failed", fmt.Sprintf("could not confine this run to a "+
			"cgroup (%v); refusing to run it", err))
	}
	cmd.SysProcAttr.UseCgroupFD = true
	cmd.SysProcAttr.CgroupFD = rcg.fd
	// Closed after the run on every path, a normal exit included: it kills
	// whatever is still in the cgroup, waits for it to empty, and removes it.
	// Dropped from `live` only after that, so a run whose teardown is still under
	// way is still accounted for.
	e.track(rcg)
	defer func() {
		rcg.close()
		e.untrack(rcg)
	}()

	started := time.Now()
	if err := cmd.Start(); err != nil {
		if pidfd >= 0 {
			_ = unix.Close(pidfd)
		}
		return sockutil.ErrorResponse(startFailure(req.Argv[0], req.Cwd, err))
	}
	// As soon as there is a pid to record, which is after the fork: the child is
	// running by then, so a run that reaches sudo before this line is refused as
	// unowned. The window is the few instructions to here against sudo's whole PAM
	// stack, and it fails closed -- an escalation nobody can attribute is refused,
	// never granted. own takes the pidfd, and closes it on the paths it does not
	// keep it.
	e.own(req.RunID, cmd.Process.Pid, pidfd)
	// A backstop for the paths that never reach the wait below; the reap is what
	// normally ends ownership, because the pid is the kernel's to reuse after it.
	defer e.disown(req.RunID)
	// This copy of the slave must go, or the master never reaches EOF.
	closeSlave()

	waitDone := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		// Before anything else learns the child is gone: once it is reaped its pid
		// is the kernel's to hand to another process, and an entry outliving the
		// reap would attribute an escalation to whatever got it.
		e.disown(req.RunID)
		close(waitDone)
	}()
	timedOut := e.await(rcg, cmd, conn, waitDone, timeoutSec, graceSec)
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

	// No duration on the wire: the broker measures a run on its own clock, and
	// the log line above is the executor's record of its half.
	return map[string]any{
		"exit_code": exitCode,
		"timed_out": timedOut,
	}
}

// await waits for the child, watching the clock and the broker's connection.
// done is closed by the caller's cmd.Wait goroutine, waiting twice failing with
// ECHILD. A timeout or a hangup ends the whole run by tearing down its cgroup,
// so a setsid descendant goes with it.
func (e *Executor) await(rcg *runCgroup, cmd *exec.Cmd, conn net.Conn, done <-chan struct{}, timeoutSec, graceSec int) bool {
	// A readable connection means the broker sent something or hung up; either way
	// the child must not outlive it.
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
		log.Printf("pid %d exceeded %ds; killing it", cmd.Process.Pid, timeoutSec)
		rcg.terminate(graceSec)
		return true
	case <-hangup:
		log.Printf("broker hung up; killing pid %d", cmd.Process.Pid)
		rcg.terminate(graceSec)
		return false
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
