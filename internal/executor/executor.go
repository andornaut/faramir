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

	out := newOutputBuffer(config.MaxOutputBytes)
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
		out.add(safe)
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
	output, truncated := out.result()
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
// response is capped in rather than the bytes a record encodes to. A ring of
// chunks rather than of bytes: chunks arrive small, and the one that overshoots
// is trimmed once.
type outputBuffer struct {
	budget int
	head   strings.Builder
	// headShut is set by the first chunk that goes to the tail. Without it the
	// head keeps taking whatever still fits, so a chunk too large for the room
	// left goes to the tail and a smaller one after it lands in the head, ahead
	// of it: the output then reads out of the order the command wrote it.
	headShut bool
	tail     []string
	tailLen  int
	dropped  int
}

func newOutputBuffer(budget int) *outputBuffer {
	return &outputBuffer{budget: budget}
}

// half is what each end gets, with room left for the marker between them.
func (b *outputBuffer) half() int { return max((b.budget-truncationMarkerReserve)/2, 1) }

// add takes one chunk. The caller keeps draining the PTY whatever this does, or
// a chatty child blocks on a full buffer and never exits.
func (b *outputBuffer) add(text string) {
	if text == "" {
		return
	}
	if !b.headShut && b.head.Len() < b.half() {
		// Cut on a rune boundary, bounded by decodeUTF8: scanning back for the
		// first valid prefix would drop everything after any invalid byte.
		keep := cutAtRune(text, b.half()-b.head.Len())
		if keep != "" {
			b.head.WriteString(keep)
			text = text[len(keep):]
		}
		if text == "" {
			return
		}
	}
	b.headShut = true
	b.tail = append(b.tail, text)
	b.tailLen += len(text)
	for b.tailLen > b.half() && len(b.tail) > 1 {
		b.dropped += len(b.tail[0])
		b.tailLen -= len(b.tail[0])
		b.tail = b.tail[1:]
	}
	// One chunk longer than the whole tail budget: keep its own tail.
	if b.tailLen > b.half() {
		keep := tailAtRune(b.tail[0], b.half())
		b.dropped += len(b.tail[0]) - len(keep)
		b.tail[0] = keep
		b.tailLen = len(keep)
	}
}

// result is what was kept, and whether anything was not.
func (b *outputBuffer) result() (string, bool) {
	head, tail := b.head.String(), strings.Join(b.tail, "")
	if b.dropped == 0 {
		return head + tail, false
	}
	return head + truncationMarker(b.dropped, b.budget) + tail, true
}

// truncationMarkerReserve is the room half() leaves for the marker. Larger than
// any marker it writes, the count being the only part that varies.
const truncationMarkerReserve = 128

func truncationMarker(dropped, budget int) string {
	return fmt.Sprintf("\n[faramir] %d bytes of output dropped; the head and the "+
		"tail are kept, at a %d byte cap\n", dropped, budget)
}

// tailAtRune is cutAtRune from the other end: the last limit bytes of s, moved
// forward only far enough not to open on a partial rune.
func tailAtRune(s string, limit int) string {
	if limit <= 0 {
		return ""
	}
	if len(s) <= limit {
		return s
	}
	cut := s[len(s)-limit:]
	for i := 0; i < utf8.UTFMax && i < len(cut); i++ {
		if utf8.RuneStart(cut[i]) {
			return cut[i:]
		}
	}
	return cut
}

func round3(v float64) float64 { return float64(int64(v*1000+0.5)) / 1000 }
