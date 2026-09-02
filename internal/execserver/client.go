package execserver

// The broker's side of the socket: one brokered command, started and then
// collected.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"golang.org/x/sys/unix"

	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

func (e *Executor) Close() error {
	if e.ln != nil {
		return e.ln.Close()
	}
	return nil
}

type ChildResult struct {
	ExitCode int
	TimedOut bool
}

// StartError is a failure the executor reported, not a transport fault: the
// command could not be started or run (a missing or non-executable program, a
// working directory it may not enter). It carries the code the caller answers
// with. Distinct from a lost or late status, where the command may have run and
// its output must be kept, so a reader can tell "did not run" from "ran, status
// unknown". Error renders "code: detail" so splitExecCode reads it as before.
type StartError struct{ Code, Detail string }

func (e *StartError) Error() string { return e.Code + ": " + e.Detail }

// Client is one brokered command: start it, then collect its exit status. Two
// calls, the broker reading the PTY master in between.
type Client struct {
	socketPath string
	conn       *net.UnixConn
}

func NewClient(socketPath string) *Client { return &Client{socketPath: socketPath} }

// ask sends one no-PTY question to the executor and returns the reply line.
// Every failure is a refusal: problem is "" only where a line came back, and
// each caller keeps its own fail-closed reading of what it got. asked names
// the question in the messages ("whether this host is quiet").
func ask(socketPath string, req request, timeout time.Duration, asked string) (line []byte, problem string) {
	conn, err := (&net.Dialer{Timeout: timeout}).DialContext(context.Background(), "unix", socketPath)
	if err != nil {
		return nil, fmt.Sprintf("the executor could not be asked %s (%s: %v)", asked, socketPath, err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	if err := sockutil.Send(conn, req); err != nil {
		return nil, fmt.Sprintf("the executor could not be asked %s (%v)", asked, err)
	}
	line, err = sockutil.ReadLine(conn, maxRequestBytes)
	if err != nil || len(line) == 0 {
		return nil, fmt.Sprintf("the executor did not say %s (%v)", asked, err)
	}
	return line, ""
}

// Quiescent asks the executor whether anything is running as its uid outside
// the runs it is confining. The broker calls this before an escalation takes;
// see Executor.quiescence for why the broker cannot answer it. Every failure
// is a no: an executor that cannot be reached has not said the host is quiet.
func Quiescent(socketPath string, timeout time.Duration) (bool, string) {
	line, problem := ask(socketPath, request{Op: opQuiescent, Version: version.Version},
		timeout, "whether this host is quiet")
	if problem != "" {
		return false, problem
	}
	var response struct {
		Quiescent bool   `json:"quiescent"`
		Detail    string `json:"detail"`
		Error     *struct {
			Message string `json:"message"`
		} `json:"error"`
	}
	if err := json.Unmarshal(line, &response); err != nil {
		return false, "the executor's answer about this host being quiet was malformed"
	}
	if response.Error != nil {
		return false, response.Error.Message
	}
	if response.Detail == "" {
		response.Detail = "the executor gave no reason"
	}
	return response.Quiescent, response.Detail
}

func (c *Client) Start(argv []string, cwd string, env map[string]string,
	stdin []byte, runID string, timeoutSec, killGraceSec int, slaveFD uintptr) error {
	addr, err := net.ResolveUnixAddr("unix", c.socketPath)
	if err != nil {
		return fmt.Errorf("executor socket %s: %w", c.socketPath, err)
	}
	conn, err := net.DialUnix("unix", nil, addr)
	if err != nil {
		return fmt.Errorf("executor socket %s: %w", c.socketPath, err)
	}
	c.conn = conn

	line, err := json.Marshal(request{
		Version: version.Version,
		Argv:    argv, Cwd: cwd, Env: env, Stdin: stdin,
		RunID:      runID,
		TimeoutSec: timeoutSec, KillGraceSec: killGraceSec,
	})
	if err != nil {
		c.Close()
		return fmt.Errorf("executor: %w", err)
	}
	line = append(line, '\n')

	rights := unix.UnixRights(int(slaveFD))
	if _, _, err := conn.WriteMsgUnix(line, rights, nil); err != nil {
		c.Close()
		return fmt.Errorf("executor: %w", err)
	}
	return nil
}

// Abort hangs up. The executor tears down the run's cgroup.
func (c *Client) Abort() { c.Close() }

func (c *Client) Result(timeout time.Duration) (*ChildResult, error) {
	if c.conn == nil {
		return nil, errors.New("executor: no command in flight")
	}
	defer c.Close()
	_ = c.conn.SetReadDeadline(time.Now().Add(timeout))

	// Bounded like a request: an executor reply is one small JSON line, so a
	// reply past the request cap is a fault, not a payload to allocate for.
	buf, err := sockutil.ReadLine(c.conn, maxRequestBytes)
	if err != nil {
		return nil, fmt.Errorf("executor: %w", err)
	}
	if len(buf) == 0 {
		return nil, errors.New("executor closed the connection without responding")
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
		return nil, fmt.Errorf("malformed response from executor: %w", err)
	}
	if response.Error != nil {
		return nil, &StartError{Code: response.Error.Code, Detail: response.Error.Message}
	}
	if response.ExitCode == nil {
		return nil, errors.New("executor response has no exit_code")
	}
	return &ChildResult{ExitCode: *response.ExitCode, TimedOut: response.TimedOut}, nil
}

func (c *Client) Close() {
	if c.conn != nil {
		_ = c.conn.Close()
		c.conn = nil
	}
}
