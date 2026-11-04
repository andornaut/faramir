package sopsrule

// What a failed sops run reports: sops's own reason, taken from its stderr,
// rather than exec's exit status.

import (
	"bytes"
	"errors"
	"fmt"
	"os/exec"
	"strings"

	"github.com/andornaut/faramir/internal/termsafe"
)

// stderrCap bounds what is kept of one run's stderr. sops's own errors are a
// few lines; the cap is for a run that prints without end.
const stderrCap = 16 << 10

// causeLines bounds how many lines of the cause an error carries, and
// causeLineBytes how long each one may be.
const (
	causeLines     = 12
	causeLineBytes = 512
)

// recoveryFooter opens the paragraph sops closes a failed decrypt with. It
// explains key groups in general and names nothing about this file.
const recoveryFooter = "Recovery failed because"

// Stderr collects a sops child's stderr, keeping the first stderrCap bytes. It
// never reports a short write: an error here would end the copy and leave the
// child blocked on, or killed by, a closed pipe.
type Stderr struct {
	buf bytes.Buffer
}

func (s *Stderr) Write(p []byte) (int, error) {
	if room := stderrCap - s.buf.Len(); room > 0 {
		s.buf.Write(p[:min(len(p), room)])
	}
	return len(p), nil
}

// Bytes is what was kept.
func (s *Stderr) Bytes() []byte { return s.buf.Bytes() }

// failure is a sops run that did not succeed. The message is sops's reason;
// Unwrap keeps the *exec.ExitError for a caller that asks for one.
type failure struct {
	msg string
	err error
}

func (f *failure) Error() string { return f.msg }
func (f *failure) Unwrap() error { return f.err }

// Failed is err from a sops run, with the reason sops gave folded in as
// indented lines under "sops refused it:". A run that printed nothing reports
// its exit status, that being all there is.
func Failed(stderr []byte, err error) error {
	return failed(stderr, err, false)
}

// FailedLine is Failed for a report with room for one line: the first line of
// the reason only.
func FailedLine(stderr []byte, err error) error {
	return failed(stderr, err, true)
}

func failed(stderr []byte, err error, oneLine bool) error {
	if _, ok := errors.AsType[*exec.ExitError](err); !ok {
		return &failure{msg: fmt.Sprintf("sops did not run: %v", err), err: err}
	}
	lines := Cause(stderr)
	switch {
	case len(lines) == 0:
		return &failure{msg: fmt.Sprintf("sops failed (%v) and printed no reason", err), err: err}
	case oneLine:
		return &failure{msg: "sops refused it: " + strings.TrimSpace(lines[0]), err: err}
	}
	return &failure{msg: "sops refused it:\n  " + strings.Join(lines, "\n  "), err: err}
}

// Cause is the lines of sops's stderr that say what went wrong, with their
// relative indentation kept and the common part removed. Dropped: blank lines,
// a first line that only introduces the lines under it ("Error unmarshalling
// file: yaml: unmarshal errors:"), and the closing paragraph of a failed
// decrypt. Each line is escaped for a terminal, and the set is bounded.
func Cause(stderr []byte) []string {
	var lines []string
	for line := range strings.SplitSeq(string(stderr), "\n") {
		line = strings.TrimRight(line, " \t\r")
		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}
		if strings.HasPrefix(trimmed, recoveryFooter) {
			break
		}
		lines = append(lines, line)
	}
	if len(lines) > 1 && strings.HasSuffix(lines[0], ":") {
		lines = lines[1:]
	}
	indent := -1
	for _, line := range lines {
		n := len(line) - len(strings.TrimLeft(line, " \t"))
		if indent < 0 || n < indent {
			indent = n
		}
	}
	more := 0
	if len(lines) > causeLines {
		more = len(lines) - causeLines
		lines = lines[:causeLines]
	}
	out := make([]string, 0, len(lines)+1)
	for _, line := range lines {
		out = append(out, termsafe.Truncate(termsafe.Line(line[indent:]), causeLineBytes))
	}
	if more > 0 {
		out = append(out, fmt.Sprintf("(%d more lines)", more))
	}
	return out
}
