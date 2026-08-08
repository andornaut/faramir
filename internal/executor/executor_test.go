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

// The PTY, the streaming redaction and the truncation are this package's, and
// they need a real child to exercise: bytes arrive in whatever chunks the
// kernel hands over, which is the whole difficulty.  They do not need a
// broker, a keeper, a sops binary or a socket the agent can reach, so this
// stands up the executor alone.

const secret = "hunter2-correct-horse-battery"

type harness struct {
	execCfg     config.ExecConfig
	executorCfg config.ExecutorConfig
	dir         string
}

func newHarness(t *testing.T, maxOutputBytes int) *harness {
	t.Helper()
	if _, err := os.Stat("/bin/sh"); err != nil {
		t.Skip("no /bin/sh")
	}
	dir := t.TempDir()
	cfg := &config.Config{
		Exec: config.ExecConfig{
			DefaultTimeoutSec: 20, MaxTimeoutSec: 30,
			MaxOutputBytes: maxOutputBytes, TermCols: 120, TermRows: 40,
			KillGraceSec: 1,
			BaseEnv:      map[string]string{"PATH": "/usr/bin:/bin"},
		},
		Executor: config.ExecutorConfig{
			SocketPath: filepath.Join(dir, "exec.sock"), SocketMode: 0o600,
			MaxConcurrency: 4,
		},
	}
	e := execserver.New(cfg)
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go e.Serve()
	t.Cleanup(func() { e.Close() })
	return &harness{execCfg: cfg.Exec, executorCfg: cfg.Executor, dir: dir}
}

// run executes a shell script and returns the result plus what the audit sink
// received, which is the other half of what this package produces.
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
				// Halves, so a script can emit the value across two writes
				// without needing a shell that can slice a variable.
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
	// The audit sink gets the redacted text too, not the raw stream.
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

// Output that ends mid-rune is the one case where the read loop has bytes left
// over after the child exits.  Feeding that tail releases whatever the
// redactor's overlap buffer no longer needs to hold, and that release is part
// of the child's output: dropping it loses characters off the end of every
// command whose last write splits a rune.
func TestOutputEndingMidRuneIsNotTruncated(t *testing.T) {
	h := newHarness(t, 1<<20)
	const width = 500
	// A lone 0xC3 is the first byte of a two-byte sequence, so the reader
	// carries it past the end of the stream.
	result, _ := h.run(t, `printf 'x%.0s' $(seq 1 500); printf '\303'`)

	if got := strings.Count(result.Output, "x"); got != width {
		t.Errorf("output holds %d of %d characters; the tail was dropped", got, width)
	}
}

// Past max_output_bytes the response is cut and says so, while the PTY keeps
// being drained: a chatty child that stopped being read would block on a full
// terminal buffer and never exit.
func TestOutputIsTruncatedButTheChildStillFinishes(t *testing.T) {
	h := newHarness(t, 4096)
	result, audited := h.run(t, `printf 'y%.0s' $(seq 1 40000); echo DONE`)

	if !result.Truncated {
		t.Error("a long run was not flagged as truncated")
	}
	if !strings.Contains(result.Output, "output truncated") {
		t.Errorf("the response does not say it was cut: %q", tail(result.Output))
	}
	if result.ExitCode != 0 {
		t.Errorf("exit = %d; the child did not finish draining", result.ExitCode)
	}
	// The audit sink has its own cap, so it keeps what the response dropped.
	if len(audited) <= len(result.Output) {
		t.Errorf("the audit sink held %d bytes, the response %d; it should hold more",
			len(audited), len(result.Output))
	}
	if !strings.Contains(audited, "DONE") {
		t.Error("the audit sink lost the end of the run")
	}
}

// A value split across two reads is still caught, which is what the overlap
// buffer is for.  Writing it a byte at a time with a pause makes the split
// happen in the kernel rather than in a constructed fixture.
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

// The exit status survives the hop through the executor, and a signalled child
// is reported as 128+signal rather than as success.
func TestExitStatusIsReported(t *testing.T) {
	h := newHarness(t, 1<<20)
	if result, _ := h.run(t, "exit 42"); result.ExitCode != 42 {
		t.Errorf("exit = %d, want 42", result.ExitCode)
	}
	if result, _ := h.run(t, "kill -TERM $$"); result.ExitCode != 128+15 {
		t.Errorf("exit = %d, want %d", result.ExitCode, 128+15)
	}
}

func tail(s string) string {
	if len(s) > 200 {
		return "..." + s[len(s)-200:]
	}
	return s
}
