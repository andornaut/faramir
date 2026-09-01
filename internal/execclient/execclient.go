// Package execclient is the broker's side of a brokered command: it owns the
// PTY and streams the child's output through the redactor. The fork is
// internal/execserver's, on the uid that holds nothing.
//
// A PTY rather than a pipe: programs format differently when stdout is a
// terminal, and a process can write straight to /dev/tty, which ssh and sudo do
// for password prompts. The cost is that stdout and stderr arrive merged.
//
// The fork happens in faramir-exec, but the PTY does not move with it: the
// broker creates the pair, hands the slave over SCM_RIGHTS and keeps the
// master, so redaction, truncation and the audit log stay on this side.
package execclient

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/andornaut/faramir/internal/audit"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/ptyutil"
	"github.com/andornaut/faramir/internal/redact"
)

const readSize = 65536

// How long past the executor's own kill deadline this waits before giving
// up.
const backstopMarginSec = 10

type Result struct {
	ExitCode    int
	Output      string
	Truncated   bool
	DurationSec float64
	TimedOut    bool
	// Abandoned is a run killed because its caller's connection went. Reported
	// separately from a timeout: both end in a killed process, and only one of
	// them is the command taking too long.
	Abandoned  bool
	Redactions []redact.Count
	// Non-zero when the command's output was not text; see redact.InvalidBytes.
	InvalidBytes int
	// StatusUnknown is a run that produced output and then went unaccounted for:
	// the executor did not report an exit status (it restarted, or the connection
	// dropped) though the command had already run. ExitCode is then a stand-in
	// kill code, never a fabricated success, and the output is still returned so
	// a caller is not told a command that ran never happened.
	StatusUnknown bool
}

// Request is one resolved command: Argv[0] is an absolute path and Env is the
// child's entire environment.
type Request struct {
	Argv []string
	Cwd  string
	Env  map[string]string
	// Stdin is what the caller piped in, for the child to read. Bounded by the
	// broker before it gets here: it travelled inside one request.
	Stdin      []byte
	TimeoutSec int
	// RunID is what the escalation server calls this run, passed through so the
	// executor can say which run forked a process asking to sudo. Empty where the
	// host grants no escalation.
	RunID string
	// Abandoned is closed when the caller's connection has gone. The run is then
	// killed rather than left to its timeout: nothing is waiting for its output,
	// and it holds a concurrency slot for as long as it would have run, so a
	// handful of interrupted callers would hold every slot for an hour.
	//
	// nil where nothing watches, which is every caller but the broker.
	Abandoned <-chan struct{}
}

// Run executes a request through the executor, returning redacted merged
// output. auditSink receives the same text before the response's truncation,
// so the log can hold more of a long run.
func Run(execCfg config.CommandConfig, executorCfg config.ExecutorConfig,
	redactor *redact.Redactor, auditSink func(string), req Request) (*Result, error) {

	argv, cwd, env, timeoutSec := req.Argv, req.Cwd, req.Env, req.TimeoutSec

	master, slave, err := ptyutil.Open()
	if err != nil {
		return nil, err
	}
	// The master must outlive the exit status: closing it SIGHUPs the child's
	// process group, and EIO only says the slave was closed, which a child does on
	// the way out.
	defer func() { _ = master.Close() }()
	ptyutil.SetWinsize(master, config.TermRows, config.TermCols)
	started := time.Now()

	client := execserver.NewClient(executorCfg.SocketPath)
	startErr := client.Start(argv, cwd, env, req.Stdin, req.RunID, timeoutSec,
		config.KillGraceSec, slave.Fd())
	// The executor holds its own copy; this one must go or the master never
	// reaches EOF.
	_ = slave.Close()
	if startErr != nil {
		return nil, startErr
	}

	out := audit.NewBounded(config.MaxOutputBytes, audit.Raw)
	aborted := false
	// The executor owns the run's cgroup and enforces the timeout; this is the
	// backstop for it not coming back at all.
	deadline := started.Add(time.Duration(timeoutSec+config.KillGraceSec+backstopMarginSec) * time.Second)

	// Every path producing output goes through here, so the log and the response
	// cannot drift apart.
	emit := func(safe string) {
		if safe == "" {
			return
		}
		if auditSink != nil {
			auditSink(safe)
		}
		out.Add(safe)
	}

	// carry holds a trailing partial UTF-8 sequence, so a rune split across two
	// reads is decoded once.
	var carry []byte
	buf := make([]byte, readSize)

	abandoned := false
	for {
		// Asked once per pass, so a run ends within one read deadline of its
		// caller going. Torn down the way an overrun is: the cgroup goes, and
		// with it everything the command started.
		if isClosed(req.Abandoned) {
			abandoned = true
			client.Abort()
			break
		}
		remaining := time.Until(deadline)
		if remaining <= 0 {
			aborted = true
			client.Abort() // hanging up tears down the run's cgroup
			break
		}
		if err := master.SetReadDeadline(time.Now().Add(min(remaining, time.Second))); err != nil {
			break
		}
		n, err := master.Read(buf)
		if n > 0 {
			carry = append(carry, buf[:n]...)
			text, rest := decodeUTF8(carry)
			carry = rest
			if text != "" {
				emit(redactor.Feed(text))
			}
		}
		if err != nil {
			if os.IsTimeout(err) {
				continue
			}
			// EIO is the normal EOF on a PTY once the child closes the slave.
			if errors.Is(err, io.EOF) || isEIO(err) {
				break
			}
			break
		}
	}

	if len(carry) > 0 {
		// Feed releases what the overlap buffer no longer needs; dropping it would
		// drop that much output.
		emit(redactor.Feed(string(carry)))
	}
	emit(redactor.Flush())

	var exitCode int
	var timedOut, statusUnknown bool
	switch {
	case abandoned:
		// Killed, so the status is the signal's, and not a timeout: the command
		// was inside the time it was given.
		exitCode = 128 + 9
	case aborted:
		exitCode, timedOut = 128+9, true
	default:
		// Wait for the status until the command's own deadline, not a fixed span:
		// a child that closed its stdout early keeps running, and the executor
		// reports only when it exits or is killed at its timeout. A short wait here
		// would cut that off and lose a status the executor was about to send. The
		// executor still enforces the timeout, so this only bounds how long a
		// vanished executor is waited for.
		result, err := client.Result(max(time.Until(deadline), time.Second))
		if err != nil {
			if _, ok := errors.AsType[*execserver.StartError](err); ok {
				// The executor reported the command could not be started or run.
				// Nothing ran and there is no output to keep, so it is returned as
				// the failure it is rather than a status-unknown run.
				return nil, err
			}
			// A transport or timeout fault: the command may have run to completion,
			// so tear the run down and decide a status rather than discarding the
			// output already collected as if nothing had run.
			client.Abort()
		}
		exitCode, timedOut, statusUnknown = exitStatus(result, err, !time.Now().Before(deadline))
	}
	output, dropped := out.Result(func(dropped int) string {
		return truncationMarker(dropped, config.MaxOutputBytes)
	})
	truncated := dropped > 0
	switch {
	case timedOut:
		output += fmt.Sprintf("\n[faramir] timed out after %ds; process killed\n", timeoutSec)
	case abandoned:
		// Written for the audit record rather than for a caller: there is nobody
		// left to read the response this goes into.
		output += "\n[faramir] the caller went away; process killed\n"
	}

	return &Result{
		ExitCode:      exitCode,
		Output:        output,
		Truncated:     truncated,
		DurationSec:   round3(time.Since(started).Seconds()),
		TimedOut:      timedOut,
		Abandoned:     abandoned,
		Redactions:    redactor.Summary(),
		InvalidBytes:  redactor.InvalidBytes(),
		StatusUnknown: statusUnknown,
	}, nil
}

// exitStatus decides a finished run's status from what the executor reported.
// Reached only once the PTY has closed, so the command ran and its output is
// already in hand: a missing or late status must not turn that into a run that
// never happened.
func exitStatus(result *execserver.ChildResult, err error, deadlinePassed bool) (
	code int, timedOut, statusUnknown bool) {
	switch {
	case err == nil:
		return result.ExitCode, result.TimedOut, false
	case deadlinePassed:
		// Waited the whole budget with no status: the run overran the backstop and
		// is torn down. A kill at the deadline is a timeout.
		return 128 + 9, true, false
	default:
		// The executor did not report though the command had already run. The
		// status cannot be known; a kill code stands in so it is never read as a
		// success, and StatusUnknown marks it as the guess it is.
		return 128 + 9, false, true
	}
}

// isClosed reports whether a channel has been closed, without blocking. A nil
// channel is never ready, which is what a caller nothing watches passes.
func isClosed(done <-chan struct{}) bool {
	select {
	case <-done:
		return true
	default:
		return false
	}
}

// decodeUTF8 returns the valid prefix of b as a string, plus any trailing bytes
// that are not valid on their own. A byte that can never start a rune is held
// back too; the caller flushes the remainder at EOF, so that costs a read
// rather than output.
func decodeUTF8(b []byte) (string, []byte) {
	// Only the last UTFMax bytes can hold an incomplete rune.
	for i := 0; i < utf8.UTFMax && i < len(b); i++ {
		idx := len(b) - 1 - i
		if !utf8.RuneStart(b[idx]) {
			continue
		}
		if utf8.Valid(b[idx:]) {
			return string(b), nil
		}
		return string(b[:idx]), append([]byte(nil), b[idx:]...)
	}
	return string(b), nil
}

func isEIO(err error) bool {
	return err != nil && strings.Contains(err.Error(), "input/output error")
}

// outputBuffer holds what a command printed, bounded by the output cap: the
// head, so the start of a run is legible, and the tail, so the end -- the
// error, the summary, the last thing it managed to say -- survives.
//
// Keeping the head alone dropped the half a failing command is read for. A run
// that printed twelve thousand lines and then the error that ended it returned
// the first six thousand and no error at all, leaving the exit code as the only
// sign of what happened, and the agent no way to find out but to run it again.
//
// The same shape audit.Collector keeps a record in, counted in the bytes the
// truncationMarker says what the response cap dropped. The response is capped
// in raw bytes rather than the bytes a record encodes to, so it carries its
// own marker; audit.Bounded is the ring under both.
func truncationMarker(dropped, budget int) string {
	return fmt.Sprintf("\n[faramir] %d bytes of output dropped; the head and the "+
		"tail are kept, at a %d byte cap\n", dropped, budget)
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
