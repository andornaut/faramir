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
	auditLog   string
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
	for _, name := range []string{"bash", "printenv", "base64", "rev", "cut", "cat", "echo", "true"} {
		dirs[binDir(t, name)] = true
	}
	var binDirs []string
	for d := range dirs {
		binDirs = append(binDirs, d)
	}

	auditLog := filepath.Join(dir, "audit.log")
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
			DefaultTimeoutSec: 30, MaxTimeoutSec: 60,
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
		Audit: config.AuditConfig{LogPath: auditLog, MaxRecordBytes: 1 << 22},
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
		dir: dir, brokerSock: cfg.Server.SocketPath, auditLog: auditLog,
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

// The harness directory is filled in unless the test named one.  The broker
// refuses a request that carries no cwd, so without this every test here would
// be exercising that refusal instead of what it is about.
func (h *harness) call(t *testing.T, request map[string]any) response {
	t.Helper()
	if _, ok := request["cwd"]; !ok && request["op"] == "exec" {
		request["cwd"] = h.dir
	}
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

// Matrix 1e/1f: no child ever receives the age key, by any name.
//
// The named variables are the obvious route.  The full dump is the one that
// matters: it catches key material arriving under a name nobody thought to
// check, which is the only way this could realistically regress.  It has to be
// asserted against a real child, because the broker assembling no such
// variable proves nothing about what the executor adds on the way.
//
// The age key is deliberately absent from the redactor's value set, so if it
// ever reached a child it would show up here in plaintext rather than as a
// token.  That is what makes the assertion meaningful rather than circular.
func TestNoAgeKeyInChildEnvironment(t *testing.T) {
	h := newHarness(t)

	r := h.runBash(t, `echo "[$SOPS_AGE_KEY][$SOPS_AGE_KEY_FILE]"`)
	if r.Error != nil {
		t.Fatalf("error: %v", r.Error)
	}
	if !strings.Contains(r.Output, "[][]") {
		t.Errorf("age key variables were set in the child: %q", r.Output)
	}

	// Bare printenv dumps the child's entire environment.
	dump := h.call(t, map[string]any{"op": "exec", "cmd": []any{"printenv"}})
	if dump.Error != nil {
		t.Fatalf("error: %v", dump.Error)
	}
	if dump.Output == "" {
		t.Fatal("the environment dump was empty; this asserts nothing")
	}
	if strings.Contains(dump.Output, "AGE-SECRET-KEY") {
		t.Errorf("AGE KEY LEAKED into a child: %q", dump.Output)
	}
	if strings.Contains(dump.Output, "SOPS_AGE") {
		t.Errorf("a SOPS_AGE_* variable reached a child: %q", dump.Output)
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

// Matrix 9: the operator's log records the invocation, and holds no value.
//
// This is the only plaintext the design would ever write to disk, so it is
// asserted at the strongest point: the exact value that was injected into this
// very command must not appear anywhere in the file.
func TestAuditLogRecordsTheRunWithoutTheValue(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":       "exec",
		"cmd":      []any{"printenv", "ROUTER_PW"},
		"env_refs": map[string]any{"ROUTER_PW": "secret://home/router/admin"},
	})
	if r.Error != nil {
		t.Fatal(r.Error)
	}
	data, err := os.ReadFile(h.auditLog)
	if err != nil {
		t.Fatal(err)
	}
	body := string(data)

	if strings.Contains(body, routerPassword) {
		t.Error("PLAINTEXT IN THE AUDIT LOG: the value reached disk unredacted")
	}
	// Present, not merely absent of secrets: an empty log audits nothing.
	if !strings.Contains(body, token) {
		t.Errorf("the output was not recorded at all: %q", body)
	}
	if !strings.Contains(body, r.LogID) {
		t.Errorf("log_id %s is not in the audit log", r.LogID)
	}
	// The ref name is what makes the record useful without the value.
	if !strings.Contains(body, "home/router/admin") {
		t.Errorf("the record does not name the ref that was injected: %q", body)
	}

	info, err := os.Stat(h.auditLog)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("audit log mode is %o, want 600", info.Mode().Perm())
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
