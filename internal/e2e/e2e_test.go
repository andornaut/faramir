// Package e2e drives a real keeper, executor and broker over real sockets.
//
// Everything runs under one uid, which exercises the protocol, the PTY
// hand-off and the redactor, but not the uid boundary itself.  The permission
// cases in the verification matrix only mean something on a real deployment,
// so they live in tests/verify.sh.
package e2e

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	sops "github.com/getsops/sops/v3"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/execserver"
	"github.com/andornaut/faramir/internal/keeper"
	"github.com/andornaut/faramir/internal/server"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/sopstest"
)

const routerPassword = "hunter2-correct-horse-battery"

type harness struct {
	dir        string
	brokerSock string
	rawLog     string
	secretFile string
	sopsBinary string
}

func binDir(t *testing.T, name string) string {
	t.Helper()
	for _, dir := range []string{"/usr/bin", "/bin", "/usr/local/bin"} {
		if _, err := os.Stat(filepath.Join(dir, name)); err == nil {
			return dir
		}
	}
	t.Skipf("%s not found; skipping", name)
	return ""
}

func newHarness(t *testing.T) *harness {
	t.Helper()

	dir := t.TempDir()
	runDir := filepath.Join(dir, "run")
	if err := os.MkdirAll(runDir, 0o755); err != nil {
		t.Fatal(err)
	}

	keyPath, recipient := sopstest.NewIdentity(t, dir)

	secretPath := filepath.Join(dir, "vault.sops.yaml")
	sopstest.WriteEncrypted(t, secretPath, recipient, sops.TreeBranch{
		{Key: "home", Value: sops.TreeBranch{
			{Key: "router", Value: sops.TreeBranch{
				{Key: "admin", Value: routerPassword},
			}},
		}},
		// A value the policy must refuse: too short to redact safely.
		{Key: "tiny", Value: "abc"},
	})

	// Collect the directories the test's programs actually live in.
	dirs := map[string]bool{}
	for _, name := range []string{"bash", "printenv", "base64", "rev", "cut", "cat", "true"} {
		dirs[binDir(t, name)] = true
	}
	var binDirs []string
	for d := range dirs {
		binDirs = append(binDirs, d)
	}

	rawLog := filepath.Join(dir, "raw.log")
	// A HOME of its own, so a sops the child runs cannot find the developer's
	// own ~/.config/sops/age/keys.txt and quietly succeed.
	childHome := filepath.Join(dir, "child-home")
	if err := os.MkdirAll(childHome, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := &config.Config{
		Path: "<test>",
		Server: config.ServerConfig{
			SocketPath: filepath.Join(runDir, "broker.sock"), SocketMode: 0o660,
			MaxConcurrency: 4, MaxRequestBytes: 262144,
		},
		Keeper: config.KeeperConfig{
			SocketPath: filepath.Join(runDir, "keeper.sock"), SocketMode: 0o660,
			AgeKeyFile: keyPath,
		},
		Executor: config.ExecutorConfig{
			SocketPath: filepath.Join(runDir, "exec.sock"), SocketMode: 0o660,
			MaxConcurrency: 8,
		},
		Exec: config.ExecConfig{
			DefaultCwd: dir, DefaultTimeoutSec: 30, MaxTimeoutSec: 60,
			MaxOutputBytes: 1 << 20,
			BaseEnv: map[string]string{
				"PATH": strings.Join(binDirs, ":"), "TERM": "xterm-256color",
				"LANG": "C.UTF-8", "LC_ALL": "C.UTF-8", "HOME": childHome,
			},
			TermCols: 120, TermRows: 40, KillGraceSec: 2,
		},
		Secrets: config.SecretsConfig{
			Files: []string{secretPath}, DecryptCommand: sopstest.DecryptCommand(t),
			RefreshIntervalSec: 0,
			MinLength:          8, MinUniqueChars: 4, MinEntropyBitsPerChar: 1.5,
		},
		Audit: config.AuditConfig{RawLog: rawLog, MaxRecordBytes: 1 << 22},
	}

	k := keeper.New(cfg)
	if _, err := k.Listen(); err != nil {
		t.Fatal(err)
	}
	go k.Serve()
	t.Cleanup(func() { k.Close() })

	e := execserver.New(cfg)
	if _, err := e.Listen(); err != nil {
		t.Fatal(err)
	}
	go e.Serve()
	t.Cleanup(func() { e.Close() })

	s := server.New(cfg)
	s.Store.Reload()
	if _, err := s.Listen(); err != nil {
		t.Fatal(err)
	}
	go s.Serve()
	t.Cleanup(func() { s.Close() })

	return &harness{
		dir: dir, brokerSock: cfg.Server.SocketPath, rawLog: rawLog,
		secretFile: secretPath, sopsBinary: sopstest.SopsBinary(t),
	}
}

type response struct {
	ExitCode   *int   `json:"exit_code"`
	Output     string `json:"output"`
	LogID      string `json:"log_id"`
	Redactions []struct {
		Token string `json:"token"`
		Count int    `json:"count"`
	} `json:"redactions"`
	Error *struct {
		Code    string `json:"code"`
		Message string `json:"message"`
	} `json:"error"`
}

func (h *harness) call(t *testing.T, request map[string]any) response {
	t.Helper()
	conn, err := net.Dial("unix", h.brokerSock)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if err := sockutil.Send(conn, request); err != nil {
		t.Fatal(err)
	}
	_ = conn.(*net.UnixConn).CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(60 * time.Second))
	line, err := sockutil.ReadLine(conn, 1<<26)
	if err != nil {
		t.Fatal(err)
	}
	var out response
	if err := json.Unmarshal(line, &out); err != nil {
		t.Fatalf("unmarshal %q: %v", line, err)
	}
	return out
}

func (h *harness) runBash(t *testing.T, script string) response {
	t.Helper()
	return h.call(t, map[string]any{
		"op":  "exec",
		"cmd": []any{"bash", "-lc", script},
		"env_refs": map[string]any{
			"ROUTER_PW": "secret://home/router/admin",
		},
	})
}

const token = "«SECRET:home/router/admin»"

// Matrix 3: the credential reaches the right variable, tokenized on the way out.
func TestExecInjectsAndRedacts(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":       "exec",
		"cmd":      []any{"printenv", "ROUTER_PW"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://home/router/admin"},
	})
	if r.Error != nil {
		t.Fatalf("error: %v", r.Error)
	}
	if !strings.Contains(r.Output, token) {
		t.Errorf("output %q does not contain %q", r.Output, token)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED: %q", r.Output)
	}
	if len(r.Redactions) == 0 || r.Redactions[0].Count < 1 {
		t.Errorf("redactions not reported: %+v", r.Redactions)
	}
}

// Matrix 1e: no child ever receives the age key.
func TestNoAgeKeyInChildEnvironment(t *testing.T) {
	h := newHarness(t)
	r := h.runBash(t, `echo "[$SOPS_AGE_KEY][$SOPS_AGE_KEY_FILE]"`)
	if r.Error != nil {
		t.Fatalf("error: %v", r.Error)
	}
	if !strings.Contains(r.Output, "[][]") {
		t.Errorf("age key variables were set in the child: %q", r.Output)
	}
	if strings.Contains(r.Output, "AGE-SECRET-KEY") {
		t.Errorf("AGE KEY LEAKED: %q", r.Output)
	}
}

// Matrix 4 and 5: base64, wrapped and unwrapped, is still caught.
func TestBase64IsRedacted(t *testing.T) {
	h := newHarness(t)
	for _, script := range []string{
		`printenv ROUTER_PW | base64`,
		`printenv ROUTER_PW | base64 -w0`,
	} {
		r := h.runBash(t, script)
		if r.Error != nil {
			t.Fatalf("%s: %v", script, r.Error)
		}
		if strings.Contains(r.Output, routerPassword) {
			t.Errorf("%s: PLAINTEXT LEAKED: %q", script, r.Output)
		}
		if !strings.Contains(r.Output, token) {
			t.Errorf("%s: not redacted: %q", script, r.Output)
		}
	}
}

// Matrix 8: an unresolvable program names [exec.base_env] PATH in the error,
// which is the one failure an operator will actually hit, so it has to be
// self-correcting rather than merely true.
func TestUnresolvableProgramNamesThePath(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "exec", "cmd": []any{"definitely-not-installed"}})
	if r.Error == nil || r.Error.Code != "exec_failed" {
		t.Fatalf("expected exec_failed: %+v", r)
	}
	for _, want := range []string{"not found on the broker's PATH", "base_env"} {
		if !strings.Contains(r.Error.Message, want) {
			t.Errorf("message does not mention %q: %q", want, r.Error.Message)
		}
	}
}

// Matrix 8b: a program outside the system directories runs.  There is no
// allowed_bin_dirs any more, and a script in the working tree is exactly the
// thing an operator wants to run.
func TestAProgramOutsideTheSystemDirectoriesRuns(t *testing.T) {
	h := newHarness(t)
	script := filepath.Join(h.dir, "deploy.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\necho DEPLOYED\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	r := h.call(t, map[string]any{"op": "exec", "cmd": []any{script}})
	if r.Error != nil {
		t.Fatalf("a working-tree script was refused: %v", r.Error)
	}
	if !strings.Contains(r.Output, "DEPLOYED") {
		t.Errorf("output = %q", r.Output)
	}

	// And by a relative path, resolved against the request's cwd rather than
	// the broker's own working directory, which would be a different file.
	r = h.call(t, map[string]any{"op": "exec", "cmd": []any{"./deploy.sh"}, "cwd": h.dir})
	if r.Error != nil {
		t.Fatalf("a relative path was refused: %v", r.Error)
	}
	if !strings.Contains(r.Output, "DEPLOYED") {
		t.Errorf("relative output = %q", r.Output)
	}
}

// A bare command with no arguments runs: there is no min_args to stop it, and
// nothing about the broker's job requires one.
func TestABareCommandRuns(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "exec", "cmd": []any{"printenv"}})
	if r.Error != nil {
		t.Fatalf("bare printenv was refused: %v", r.Error)
	}
	// It dumps the child's environment, which must not contain the age key.
	if strings.Contains(r.Output, "AGE-SECRET-KEY") {
		t.Errorf("AGE KEY LEAKED: %q", r.Output)
	}
}

// A string cmd must be refused with guidance, never handed to a shell.
func TestStringCmdIsRefused(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "exec", "cmd": "printenv ROUTER_PW"})
	if r.Error == nil || r.Error.Code != "bad_request" {
		t.Fatalf("string cmd was not refused: %+v", r)
	}
	if !strings.Contains(r.Error.Message, "must be an array") {
		t.Errorf("unhelpful message: %q", r.Error.Message)
	}
}

// Reserved names cannot be overwritten by the caller.
func TestReservedEnvIsRefused(t *testing.T) {
	h := newHarness(t)
	for _, name := range []string{"PATH", "LD_PRELOAD", "SOPS_AGE_KEY"} {
		r := h.call(t, map[string]any{
			"op": "exec", "cmd": []any{"printenv", name},
			"env_refs": map[string]any{name: "secret://home/router/admin"},
		})
		if r.Error == nil || r.Error.Code != "bad_request" {
			t.Errorf("%s was not refused: %+v", name, r)
		}
	}
}

// Matrix 9: the unredacted stream is in the operator's log.
func TestRawLogHoldsPlaintext(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":       "exec",
		"cmd":      []any{"printenv", "ROUTER_PW"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://home/router/admin"},
	})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	data, err := os.ReadFile(h.rawLog)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), routerPassword) {
		t.Error("raw log does not contain the plaintext; the operator cannot debug")
	}
	if !strings.Contains(string(data), r.LogID) {
		t.Errorf("log_id %s is not in the raw log", r.LogID)
	}
	info, err := os.Stat(h.rawLog)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("raw log mode is %o, want 600", info.Mode().Perm())
	}
}

// Matrix 10 and 11.  These are NOT defects: an agent that deliberately
// transforms a value defeats output redaction, and with unrestricted egress
// that value is gone.  They are asserted to keep leaking so that a future
// change which appears to fix them is caught and forces the threat model to be
// revisited rather than silently outgrown.
func TestAdversarialTransformsStillLeak(t *testing.T) {
	h := newHarness(t)

	reversed := reverse(routerPassword)
	r := h.runBash(t, `printenv ROUTER_PW | rev`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if !strings.Contains(r.Output, reversed) {
		t.Fatalf("matrix test 10 no longer leaks (output %q). This is not a fix to "+
			"celebrate: revisit the threat model in the README before changing this "+
			"assertion, because the matcher cannot be completed.", r.Output)
	}

	r = h.runBash(t, `printenv ROUTER_PW | cut -c1-4`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if !strings.Contains(r.Output, routerPassword[:4]) {
		t.Fatalf("matrix test 11 no longer leaks (output %q); see the note above.", r.Output)
	}
}

// A short value is refused at load: it cannot be redacted, so it is not
// injectable, and the denial says so rather than reporting a typo.
func TestShortSecretIsRefusedAtLoad(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op": "exec", "cmd": []any{"printenv", "TINY"},
		"env_refs": map[string]any{"TINY": "secret://tiny"},
	})
	if r.Error == nil || r.Error.Code != "unknown_secret" {
		t.Fatalf("short secret was injectable: %+v", r)
	}
	if !strings.Contains(r.Error.Message, "refused at load") {
		t.Errorf("message does not explain the refusal: %q", r.Error.Message)
	}

	// It must also be absent from list_secrets.
	list := h.call(t, map[string]any{"op": "list_secrets"})
	if strings.Contains(list.Output, "secret://tiny") {
		t.Error("a refused secret was listed")
	}
	if !strings.Contains(list.Output, "secret://home/router/admin") {
		t.Errorf("loaded secret missing from list: %q", list.Output)
	}
}

// Matrix 7b: a brokered command cannot decrypt the secret store itself.  This
// is the property that lets Ansible be one consumer of the broker rather than
// a holder of the master key: the child gets named values or nothing.
func TestABrokeredCommandCannotDecryptTheStore(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":  "exec",
		"cmd": []any{h.sopsBinary, "--output-type", "json", "--decrypt", h.secretFile},
	})
	if r.Error != nil {
		t.Fatalf("sops did not even start: %v", r.Error)
	}
	if r.ExitCode == nil || *r.ExitCode == 0 {
		t.Fatalf("a child decrypted the store: exit=%v output=%q", r.ExitCode, r.Output)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED: %q", r.Output)
	}
	// It has to fail for want of key material, not because sops was missing or
	// mis-invoked, or this passes for the wrong reason forever.
	if !strings.Contains(r.Output, "data key") && !strings.Contains(r.Output, "master key") {
		t.Errorf("sops failed for some other reason than a missing key: %q", r.Output)
	}
}

// The reason for the PTY: ssh and sudo write their prompts straight to
// /dev/tty, which no pipe on stdout or stderr would ever see.  Captured is
// half of it; redacted is the half that matters.
func TestWritesToDevTtyAreCapturedAndRedacted(t *testing.T) {
	h := newHarness(t)
	r := h.runBash(t, `printenv ROUTER_PW > /dev/tty`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED to /dev/tty: %q", r.Output)
	}
	if !strings.Contains(r.Output, token) {
		t.Errorf("a /dev/tty write was not captured: %q", r.Output)
	}
}

// Output that ends mid-rune is the one case where the read loop has bytes left
// over after the child exits.  Feeding that tail releases whatever the
// redactor's overlap buffer no longer needs to hold, and that release is part
// of the child's output: dropping it silently loses characters from the end of
// every command whose last write splits a rune.
func TestOutputEndingMidRuneIsNotTruncated(t *testing.T) {
	h := newHarness(t)
	const width = 500
	r := h.call(t, map[string]any{
		"op": "exec",
		// A lone 0xC3 is the first byte of a two-byte sequence, so the reader
		// carries it past the end of the stream.
		"cmd": []any{"bash", "-lc", `printf 'x%.0s' $(seq 1 500); printf '\303'`},
	})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if got := strings.Count(r.Output, "x"); got != width {
		t.Errorf("output holds %d of %d characters; the tail was dropped", got, width)
	}
}

// A PTY, not a pipe: the child must see a terminal on stdout.
func TestChildGetsATerminal(t *testing.T) {
	h := newHarness(t)
	r := h.runBash(t, `test -t 1 && echo IS_TTY || echo NOT_TTY`)
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if !strings.Contains(r.Output, "IS_TTY") {
		t.Errorf("child did not get a terminal: %q", r.Output)
	}
}

// stdin is /dev/null, so an interactive prompt fails immediately rather than
// hanging and holding a concurrency slot.
func TestStdinIsClosed(t *testing.T) {
	h := newHarness(t)
	done := make(chan response, 1)
	go func() { done <- h.runBash(t, `read -r line; echo "got:[$line]"`) }()
	select {
	case r := <-done:
		if !strings.Contains(r.Output, "got:[]") {
			t.Errorf("unexpected output: %q", r.Output)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("a command reading stdin hung; stdin is not /dev/null")
	}
}

func TestStatusReportsNoValues(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "status"})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Error("status leaked a value")
	}
	if !strings.Contains(r.Output, "ref_count") {
		t.Errorf("status is missing ref_count: %q", r.Output)
	}
	// The operator-only refusal list must not be on the agent-facing wire.
	if strings.Contains(r.Output, "not_redactable") {
		t.Error("status exposed the not_redactable list to the agent")
	}
}

// Inline {{SECRET:ref}} becomes a shell variable reference, never a value.
func TestInlineTokenNeverExpandsBrokerSide(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":  "exec",
		"cmd": []any{"bash", "-lc", `echo "{{SECRET:home/router/admin}}"`},
	})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	// The shell expands it, so the value reaches the output and is redacted;
	// what matters is that it never appeared in argv.
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED: %q", r.Output)
	}
	if !strings.Contains(r.Output, token) {
		t.Errorf("inline token did not resolve to the secret: %q", r.Output)
	}
}

func reverse(s string) string {
	r := []rune(s)
	for i, j := 0, len(r)-1; i < j; i, j = i+1, j-1 {
		r[i], r[j] = r[j], r[i]
	}
	return string(r)
}
