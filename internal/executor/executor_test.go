package executor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/redact"
)

// The PTY, the streaming redaction and the truncation need a real child, since
// bytes arrive in whatever chunks the kernel hands over. They need no broker,
// keeper, sops or agent-reachable socket.

const secret = "hunter2-correct-horse-battery"

type harness struct {
	execCfg     config.CommandConfig
	executorCfg config.ExecutorConfig
	dir         string
}

func newHarness(t *testing.T, maxOutputBytes int) *harness {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	// The response bound is a package variable rather than a key, so a test that
	// narrowed it and did not restore it would narrow every test after it.
	was := config.MaxOutputBytes
	config.MaxOutputBytes = maxOutputBytes
	t.Cleanup(func() { config.MaxOutputBytes = was })
	dir := t.TempDir()
	cfg := &config.Config{
		Command: config.CommandConfig{
			TimeoutSec: 20, MaxTimeoutSec: 30, Env: map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Executor: config.ExecutorConfig{
			SocketPath: filepath.Join(dir, "exec.sock"),
		},
	}
	e := execserver.New(cfg)
	// Every brokered command is confined to its own cgroup, so an executor without
	// a delegated one refuses all of them and there is no output to assert on. CI
	// delegates a cgroup to the runner and exercises the real path; run under
	// `systemd-run --user --scope go test ./...` to do the same locally.
	if !e.CanConfine() {
		t.Skip("no delegated cgroup on this host; the executor refuses every command here")
	}
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go func() { _ = e.Serve() }()
	t.Cleanup(func() { _ = e.Close() })
	return &harness{execCfg: cfg.Command, executorCfg: cfg.Executor, dir: dir}
}

// run executes a shell script and returns the result plus what the audit sink
// received.
func (h *harness) run(t *testing.T, script string) (*Result, string) {
	t.Helper()
	r := redact.New([]redact.Secret{{Ref: "a/b", Value: secret}}, redact.DefaultPolicy())
	var audited strings.Builder
	result, err := Run(h.execCfg, h.executorCfg, r, func(s string) { audited.WriteString(s) },
		Request{
			Argv: []string{"/bin/sh", "-c", script},
			Cwd:  h.dir,
			Env: map[string]string{
				"PATH": "/usr/bin:/bin", "SECRET": secret,
				// Halves, so a script can emit the value in two writes.
				"HALF_A": secret[:10], "HALF_B": secret[10:],
			},
			TimeoutSec: 10,
		})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	return result, audited.String()
}

func TestOutputIsRedactedAsItStreams(t *testing.T) {
	h := newHarness(t, 1<<20)
	result, audited := h.run(t, `printf '%s\n' "$SECRET"`)

	token := redact.TokenFor("a/b")
	if strings.Contains(result.Output, secret) {
		t.Errorf("PLAINTEXT LEAKED: %q", result.Output)
	}
	if !strings.Contains(result.Output, token) {
		t.Errorf("output = %q, want the token", result.Output)
	}
	// The sink gets the redacted text, not the raw stream.
	if strings.Contains(audited, secret) {
		t.Errorf("PLAINTEXT REACHED THE AUDIT SINK: %q", audited)
	}
	if !strings.Contains(audited, token) {
		t.Errorf("the audit sink saw %q", audited)
	}
	if len(result.Redactions) != 1 || result.Redactions[0].Count != 1 {
		t.Errorf("redactions = %+v", result.Redactions)
	}
}

// The one case where the read loop has bytes left after the child exits.
// Feeding that tail releases what the overlap buffer no longer needs, which is
// itself output.
func TestOutputEndingMidRuneIsNotTruncated(t *testing.T) {
	h := newHarness(t, 1<<20)
	const width = 500
	// A lone 0xC3 opens a two-byte sequence, so the reader carries it past the end
	// of the stream.
	result, _ := h.run(t, `printf 'x%.0s' $(seq 1 500); printf '\303'`)

	if got := strings.Count(result.Output, "x"); got != width {
		t.Errorf("output holds %d of %d characters; the tail was dropped", got, width)
	}
}

// The response is cut and says so, while the PTY keeps being drained: a chatty
// child that stopped being read would block and never exit. What the cut keeps
// is the head and the tail, so the last thing the child said is in it: that is
// the line a run is read for, and a command's own `DONE` stands in for it.
func TestOutputIsTruncatedButTheChildStillFinishes(t *testing.T) {
	h := newHarness(t, 4096)
	result, audited := h.run(t, `printf 'y%.0s' $(seq 1 40000); echo DONE`)

	if !result.Truncated {
		t.Error("a long run was not flagged as truncated")
	}
	if !strings.Contains(result.Output, "bytes of output dropped") {
		t.Errorf("the response does not say it was cut: %q", tail(result.Output))
	}
	if !strings.Contains(result.Output, "DONE") {
		t.Errorf("the end of the output was dropped: %q", tail(result.Output))
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d; the child did not finish draining", result.ExitCode)
	}
	// The sink has its own cap, so it keeps what the response dropped.
	if len(audited) <= len(result.Output) {
		t.Errorf("the audit sink held %d bytes, the response %d; it should hold more",
			len(audited), len(result.Output))
	}
	if !strings.Contains(audited, "DONE") {
		t.Error("the audit sink lost the end of the run")
	}
}

// What the overlap buffer is for. Written a byte at a time so the split
// happens in the kernel rather than in a fixture.
func TestAValueSplitAcrossReadsIsStillCaught(t *testing.T) {
	h := newHarness(t, 1<<20)
	result, _ := h.run(t, `printf '%s' "$HALF_A"; sleep 0.2; printf '%s\n' "$HALF_B"`)

	if strings.Contains(result.Output, secret) {
		t.Errorf("PLAINTEXT LEAKED across a read boundary: %q", result.Output)
	}
	if !strings.Contains(result.Output, redact.TokenFor("a/b")) {
		t.Errorf("output = %q, want the token", result.Output)
	}
}

// The exit status survives the hop, and a signalled child is 128+signal.
func TestExitStatusIsReported(t *testing.T) {
	h := newHarness(t, 1<<20)
	if result, _ := h.run(t, "exit 42"); result.ExitCode != 42 {
		t.Errorf("exit = %d, want 42", result.ExitCode)
	}
	if result, _ := h.run(t, "kill -TERM $$"); result.ExitCode != 128+15 {
		t.Errorf("exit = %d, want %d", result.ExitCode, 128+15)
	}
}

// EIO on the master says the slave was closed, not that the child is gone, and
// closing the master before the status is collected would turn every such exit
// into 129. Closing the descriptors explicitly widens that window to the whole
// run.
func TestAChildThatClosesTheTerminalKeepsItsExitCode(t *testing.T) {
	h := newHarness(t, 1<<20)
	result, _ := h.run(t, `exec 1>&- 2>&-; sleep 0.3; exit 7`)

	if result.ExitCode != 7 {
		t.Errorf("exit = %d, want 7", result.ExitCode)
	}
}

func tail(s string) string {
	if len(s) > 200 {
		return "..." + s[len(s)-200:]
	}
	return s
}

// The abort path flushes what the child printed before it. A command killed at
// its deadline has usually written something first, and that text goes to the
// caller and to the audit sink like any other: leaving it unredacted would make
// the timeout a way to print a value in the clear.
func TestOutputPrintedBeforeATimeoutIsStillRedacted(t *testing.T) {
	h := newHarness(t, 1<<20)
	r := redact.New([]redact.Secret{{Ref: "a/b", Value: secret}}, redact.DefaultPolicy())
	var audited strings.Builder
	result, err := Run(h.execCfg, h.executorCfg, r, func(s string) { audited.WriteString(s) },
		Request{
			Argv: []string{"/bin/sh", "-c", `printf '%s\n' "$SECRET"; sleep 30`},
			Cwd:  h.dir,
			Env:  map[string]string{"PATH": "/usr/bin:/bin", "SECRET": secret},
			// Shorter than the sleep, so the kill is what ends the run.
			TimeoutSec: 1,
		})
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if !result.TimedOut {
		t.Fatal("the run ended without timing out, so the abort path was never taken")
	}
	if strings.Contains(result.Output, secret) {
		t.Errorf("PLAINTEXT LEAKED on the timeout path: %q", result.Output)
	}
	if !strings.Contains(result.Output, redact.TokenFor("a/b")) {
		t.Errorf("output = %q, want what was printed before the kill, tokenized", result.Output)
	}
	if strings.Contains(audited.String(), secret) {
		t.Errorf("PLAINTEXT REACHED THE AUDIT SINK on the timeout path: %q", audited.String())
	}
}
