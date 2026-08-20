// Package executor owns the PTY and streams the child's output through the
// redactor. A PTY rather than a pipe: programs format differently when stdout
// is a terminal, and a process can write straight to /dev/tty, which ssh and
// sudo do for password prompts. The cost is that stdout and stderr arrive
// merged.
//
// The fork happens in faramir-exec, but the PTY does not move with it: the
// broker creates the pair, hands the slave over SCM_RIGHTS and keeps the
// master, so redaction, truncation and the audit log stay on this side.
package executor

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
	"unicode/utf8"

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
	Redactions  []redact.Count
	// Non-zero when the command's output was not text; see redact.InvalidBytes.
	InvalidBytes int
}

// Request is one resolved command: Argv[0] is an absolute path and Env is the
// child's entire environment.
type Request struct {
	Argv       []string
	Cwd        string
	Env        map[string]string
	TimeoutSec int
	// RunID is what the escalation server calls this run, passed through so the
	// executor can say which run forked a process asking to sudo. Empty where the
	// host grants no escalation.
	RunID string
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
	ptyutil.SetWinsize(master.Fd(), config.TermRows, config.TermCols)
	started := time.Now()

	client := execserver.NewClient(executorCfg.SocketPath)
	startErr := client.Start(argv, cwd, env, req.RunID, timeoutSec, config.KillGraceSec, slave.Fd())
	// The executor holds its own copy; this one must go or the master never
	// reaches EOF.
	_ = slave.Close()
	if startErr != nil {
		return nil, startErr
	}

	var chunks strings.Builder
	emitted := 0
	truncated := false
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
		emitted, truncated = appendOutput(&chunks, safe, emitted, config.MaxOutputBytes, truncated)
	}

	// carry holds a trailing partial UTF-8 sequence, so a rune split across two
	// reads is decoded once.
	var carry []byte
	buf := make([]byte, readSize)

	for {
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
	var timedOut bool
	if aborted {
		exitCode, timedOut = 128+9, true
	} else {
		result, err := client.Result(30 * time.Second)
		if err != nil {
			return nil, err
		}
		exitCode, timedOut = result.ExitCode, result.TimedOut
	}
	output := chunks.String()
	if timedOut {
		output += fmt.Sprintf("\n[faramir] timed out after %ds; process killed\n", timeoutSec)
	}

	return &Result{
		ExitCode:     exitCode,
		Output:       output,
		Truncated:    truncated,
		DurationSec:  round3(time.Since(started).Seconds()),
		TimedOut:     timedOut,
		Redactions:   redactor.Summary(),
		InvalidBytes: redactor.InvalidBytes(),
	}, nil
}

// cutAtRune returns the first limit bytes of s, backing off only far enough not
// to end on a partial rune. Bounded like decodeUTF8: raw PTY bytes can be
// invalid anywhere, and must not take the rest of the chunk with them.
func cutAtRune(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	cut := s[:limit]
	for i := 1; i < utf8.UTFMax && i <= len(cut); i++ {
		start := len(cut) - i
		if !utf8.RuneStart(cut[start]) {
			continue
		}
		if utf8.ValidString(cut[start:]) {
			return cut // the last rune is whole
		}
		return cut[:start]
	}
	return cut
}

// decodeUTF8 returns the complete prefix of b as a string, plus any trailing
// bytes that form an incomplete rune.
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

// appendOutput appends output up to limit bytes. The caller keeps draining the
// PTY, or a chatty child blocks on a full buffer and never exits.
func appendOutput(chunks *strings.Builder, text string, emitted, limit int, truncated bool) (int, bool) {
	if truncated {
		return emitted, true
	}
	size := len(text)
	if emitted+size <= limit {
		chunks.WriteString(text)
		return emitted + size, false
	}
	if room := limit - emitted; room > 0 {
		// Cut on a rune boundary, bounded by decodeUTF8: scanning back for the
		// first valid prefix would drop everything after any invalid byte.
		chunks.WriteString(cutAtRune(text, room))
	}
	_, _ = fmt.Fprintf(chunks, "\n[faramir] output truncated at %d bytes\n", limit)
	return limit, true
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
