// Package executor owns the PTY and streams the child's output through the
// redactor.
//
// Why a PTY and not a pipe:
//
//  1. Programs behave normally when stdout is a terminal: colour, progress
//     meters, line buffering.  Ansible in particular formats very differently.
//  2. A process can write straight to /dev/tty, bypassing stdout redirection
//     entirely; ssh and sudo do exactly this for password prompts.  Owning the
//     controlling terminal catches those writes.  A pipe does not.
//
// The consequence is that stdout and stderr arrive merged.  That is accepted.
//
// The fork happens in faramir-exec, under a uid that holds nothing, but the
// PTY does not move with it: the broker creates the pair, hands the slave over
// SCM_RIGHTS and keeps the master.  Redaction, truncation and the audit log
// therefore stay on this side, reading the child's bytes directly, with no
// extra hop for output to take.
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

// How long past the executor's own kill deadline we wait before giving up.
const backstopMarginSec = 10

type Result struct {
	ExitCode    int
	Output      string
	Truncated   bool
	DurationSec float64
	TimedOut    bool
	Redactions  []redact.Count
}

// Run executes argv through the executor, returning redacted merged output.
//
// rawSink receives the unredacted text for the operator-only audit log.
// Nothing else in this process ever sees it.
func Run(argv []string, cwd string, env map[string]string, timeoutSec int,
	redactor *redact.Redactor, execCfg config.ExecConfig, executorCfg config.ExecutorConfig,
	rawSink func(string)) (*Result, error) {

	master, slave, err := ptyutil.Open()
	if err != nil {
		return nil, err
	}
	ptyutil.SetWinsize(master.Fd(), execCfg.TermRows, execCfg.TermCols)
	started := time.Now()

	client := execserver.NewClient(executorCfg.SocketPath)
	startErr := client.Start(argv, cwd, env, timeoutSec, execCfg.KillGraceSec, slave.Fd())
	// The executor has its own copy now.  Ours has to go, or the master never
	// reaches EOF when the child exits.
	_ = slave.Close()
	if startErr != nil {
		_ = master.Close()
		return nil, startErr
	}

	var chunks strings.Builder
	emitted := 0
	truncated := false
	aborted := false
	// The executor enforces the timeout, because it owns the process group.
	// This is a backstop for the case where it does not come back at all.
	deadline := started.Add(time.Duration(timeoutSec+execCfg.KillGraceSec+backstopMarginSec) * time.Second)

	// carry holds bytes that end in a partial UTF-8 sequence, so a rune split
	// across two reads is decoded once rather than replaced twice.
	var carry []byte
	buf := make([]byte, readSize)

	for {
		remaining := time.Until(deadline)
		if remaining <= 0 {
			aborted = true
			client.Abort() // hanging up kills the child's process group
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
				if rawSink != nil {
					rawSink(text)
				}
				if safe := redactor.Feed(text); safe != "" {
					emitted, truncated = appendOutput(&chunks, safe, emitted, execCfg.MaxOutputBytes, truncated)
				}
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
		tail := string(carry)
		if rawSink != nil {
			rawSink(tail)
		}
		redactor.Feed(tail)
	}
	if final := redactor.Flush(); final != "" {
		emitted, truncated = appendOutput(&chunks, final, emitted, execCfg.MaxOutputBytes, truncated)
	}
	_ = master.Close()

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
		ExitCode:    exitCode,
		Output:      output,
		Truncated:   truncated,
		DurationSec: round3(time.Since(started).Seconds()),
		TimedOut:    timedOut,
		Redactions:  redactor.Summary(),
	}, nil
}

// decodeUTF8 returns the complete prefix of b as a string, plus any trailing
// bytes that form an incomplete rune.
func decodeUTF8(b []byte) (string, []byte) {
	// Only the last UTFMax bytes can hold an incomplete rune, so the search is
	// bounded and the carry can never grow without limit.
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

// appendOutput appends output up to limit bytes; the caller keeps draining the
// PTY after that.  Draining matters: if we stopped reading, a chatty child
// would block on a full PTY buffer and never exit.
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
		// Cut on a rune boundary so the tail is not a broken character.
		cut := text[:room]
		for len(cut) > 0 && !utf8.ValidString(cut) {
			cut = cut[:len(cut)-1]
		}
		chunks.WriteString(cut)
	}
	chunks.WriteString(fmt.Sprintf("\n[faramir] output truncated at %d bytes\n", limit))
	return limit, true
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
