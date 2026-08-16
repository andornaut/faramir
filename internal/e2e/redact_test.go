package e2e

import (
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// guardRewrite returns what the hook would replace a Bash command with.
func guardRewrite(t *testing.T, cliPath, command string) string {
	t.Helper()
	payload, err := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	if err != nil {
		t.Fatal(err)
	}
	// The same binary the settings file registers.
	hook := exec.CommandContext(t.Context(), cliPath, "guard")
	hook.Stdin = strings.NewReader(string(payload))
	wrap, err := filepath.Abs("../../agent/hooks/wrap.sh")
	if err != nil {
		t.Fatal(err)
	}
	hook.Env = append(os.Environ(), "FARAMIR_CLI="+cliPath, "FARAMIR_WRAP="+wrap)
	out, err := hook.Output()
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	var decoded struct {
		Hook struct {
			UpdatedInput struct {
				Command string `json:"command"`
			} `json:"updatedInput"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(out, &decoded); err != nil {
		t.Fatalf("unmarshal %q: %v", out, err)
	}
	if decoded.Hook.UpdatedInput.Command == "" {
		t.Fatalf("the guard did not rewrite %q: %s", command, out)
	}
	return decoded.Hook.UpdatedInput.Command
}

// Run for real, in one shell, twice, as the agent's Bash tool does: a wrapper
// using a subshell or a pipeline loses the session's state here.
func TestTheRewrittenCommandRedactsAndKeepsShellState(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)

	first := guardRewrite(t, cli, "cd /var; export FR_KEPT=yes; echo leaked:"+routerPassword)
	second := guardRewrite(t, cli, `echo "pwd=$PWD kept=${FR_KEPT:-lost}"`)

	session := exec.CommandContext(t.Context(), "bash", "-c", first+"\n"+second+"\n")
	session.Dir = "/tmp"
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli,
		privateRuntimeEnv(t))
	out, err := session.CombinedOutput()
	if err != nil {
		t.Fatalf("running the rewritten commands: %v: %s", err, out)
	}
	got := string(out)

	if strings.Contains(got, routerPassword) {
		t.Errorf("the value survived the rewrite: %q", got)
	}
	if !strings.Contains(got, token) {
		t.Errorf("output = %q, want the %s token", got, token)
	}
	// The state the first command set reaches the second.
	if !strings.Contains(got, "pwd=/var") {
		t.Errorf("output = %q, want cd to have persisted to the next command", got)
	}
	if !strings.Contains(got, "kept=yes") {
		t.Errorf("output = %q, want export to have persisted to the next command", got)
	}
}

// privateRuntimeEnv gives the wrapper the private XDG_RUNTIME_DIR it insists on:
// a directory owned by this uid that no other account can read.  A real session
// has one at /run/user/<uid>; a bare test process may not (nor may CI), so the
// tests provide their own rather than depend on the ambient environment.
// t.TempDir is this uid's; the chmod clears the group and other bits the
// wrapper's `stat` check refuses.
func privateRuntimeEnv(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	return "XDG_RUNTIME_DIR=" + dir
}

// runWrapped runs a rewritten command the way the agent's shell would, keeping
// stdout and stderr apart: the agent reads stdout.
func runWrapped(t *testing.T, rewritten string, env ...string) (stdout, stderr string, code int) {
	t.Helper()
	session := exec.CommandContext(t.Context(), "bash", "-c", rewritten)
	session.Env = append(os.Environ(), env...)
	var out, errs strings.Builder
	session.Stdout, session.Stderr = &out, &errs
	err := session.Run()
	var exitErr *exec.ExitError
	switch {
	case err == nil:
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	default:
		t.Fatalf("running the rewritten command: %v", err)
	}
	return out.String(), errs.String(), code
}

// Output that could not be redacted is withheld rather than shown; a broker that
// is not there is the ordinary way this happens.
func TestTheWrapperWithholdsOutputItCouldNotRedact(t *testing.T) {
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo leaked:"+routerPassword)

	stdout, stderr, code := runWrapped(t, rewritten,
		"FARAMIR_SOCKET="+filepath.Join(t.TempDir(), "absent.sock"), "FARAMIR_CLI="+cli,
		privateRuntimeEnv(t))

	if strings.Contains(stdout, routerPassword) {
		t.Errorf("the value reached the agent unredacted: %q", stdout)
	}
	if strings.Contains(stdout, "leaked:") {
		t.Errorf("stdout = %q, want the output withheld entirely", stdout)
	}
	if !strings.Contains(stderr, "withheld") {
		t.Errorf("stderr = %q, want it to say the output was withheld", stderr)
	}
	// Withholding and reporting success would read as a command that printed
	// nothing.
	if code == 0 {
		t.Error("a withheld output was reported as a clean success")
	}
}

// With nowhere to capture output the command does not run at all, running it
// being output sent straight through.
func TestTheWrapperDoesNotRunACommandItCannotCapture(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)
	marker := filepath.Join(t.TempDir(), "ran")
	rewritten := guardRewrite(t, cli, "echo "+routerPassword+" > "+marker)

	// Shadow mktemp rather than simulate a full /dev/shm.
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "mktemp"),
		[]byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	// A private runtime directory, so the wrapper gets past that check and the
	// shadowed mktemp is the only thing left to refuse on.  Without it a host with
	// no XDG_RUNTIME_DIR refuses for that reason instead, and the assertions below
	// hold without the shim having done anything.
	stdout, stderr, code := runWrapped(t, rewritten, "PATH="+shim+":"+os.Getenv("PATH"),
		"FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli, privateRuntimeEnv(t))

	if _, err := os.Stat(marker); err == nil {
		t.Error("the command ran even though its output could not be captured")
	}
	if strings.Contains(stdout, routerPassword) {
		t.Errorf("the value reached the agent unredacted: %q", stdout)
	}
	if !strings.Contains(stderr, "not run") {
		t.Errorf("stderr = %q, want it to say the command was not run", stderr)
	}
	if code == 0 {
		t.Error("a command that never ran was reported as a clean success")
	}
}

// A failing command keeps failing, or every check an agent runs reads as a
// pass.
func TestTheRewrittenCommandKeepsTheExitCode(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo before; (exit 33)")

	session := exec.CommandContext(t.Context(), "bash", "-c", rewritten)
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli,
		privateRuntimeEnv(t))
	out, err := session.CombinedOutput()
	var exitErr *exec.ExitError
	if !strings.Contains(string(out), "before") {
		t.Errorf("output = %q, want the command's own output", out)
	}
	if err == nil {
		t.Fatal("the rewritten command exited 0, want 33")
	}
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 33 {
		t.Errorf("exit = %v, want 33", err)
	}
}

// The wrapper's temporary file must not be left behind holding unredacted
// output.
func TestTheRewriteLeavesNoTemporaryFile(t *testing.T) {
	h := newHarness(t)
	// A stand-in for the real XDG_RUNTIME_DIR, which is the session's own tmpfs at
	// 0700.  t.TempDir hands back 0775, and the hook refuses to capture unredacted
	// output into a directory another account can read.
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo "+routerPassword)

	session := exec.CommandContext(t.Context(), "bash", "-c", rewritten)
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock,
		"FARAMIR_CLI="+cli, "XDG_RUNTIME_DIR="+dir)
	if out, err := session.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	left, err := filepath.Glob(filepath.Join(dir, "faramir.*"))
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Errorf("left behind: %v", left)
	}
}

// A command that runs "exit" ends the sourced shell at the eval, before the
// cleanup, and the capture file at that point holds output nothing has redacted
// yet.  An EXIT trap is what still runs on that path.
func TestTheRewriteLeavesNoTemporaryFileWhenTheCommandExits(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo "+routerPassword+"; exit 42")

	session := exec.CommandContext(t.Context(), "bash", "-c", rewritten)
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock,
		"FARAMIR_CLI="+cli, "XDG_RUNTIME_DIR="+dir)
	out, err := session.CombinedOutput()

	// The status the command chose still reaches the caller.
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 42 {
		t.Errorf("exit = %v, want 42", err)
	}
	if strings.Contains(string(out), routerPassword) {
		t.Errorf("the value reached the caller: %q", out)
	}
	left, err := filepath.Glob(filepath.Join(dir, "faramir.*"))
	if err != nil {
		t.Fatal(err)
	}
	for _, path := range left {
		body, _ := os.ReadFile(path)
		t.Errorf("left behind %s holding %q", path, body)
	}
}

// Fails closed: with nowhere private to capture into, the command does not run
// at all.  Running it would print whatever it found straight to the agent, and
// capturing into a directory another account can write is not a capture whose
// contents this can answer for.
func TestTheRewriteRefusesWithoutAPrivateRuntimeDir(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo "+routerPassword)

	shared := t.TempDir()
	if err := os.Chmod(shared, 0o777); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		dir  string
	}{
		{"unset, as under sudo and in cron", ""},
		{"a directory other accounts can write", shared},
	} {
		t.Run(tc.name, func(t *testing.T) {
			session := exec.CommandContext(t.Context(), "bash", "-c", rewritten)
			session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock,
				"FARAMIR_CLI="+cli, "XDG_RUNTIME_DIR="+tc.dir)
			out, err := session.CombinedOutput()

			if err == nil {
				t.Errorf("the command was run anyway: %s", out)
			}
			if strings.Contains(string(out), routerPassword) {
				t.Errorf("the value reached the caller: %q", out)
			}
			if !strings.Contains(string(out), "was not run") {
				t.Errorf("output does not say the command was withheld: %q", out)
			}
		})
	}
}

// The redact op gives a session outside the broker's uid the same redaction a
// brokered command gets.
func TestRedactOpTokenizesAValueTheCallerAlreadyHolds(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{
		"op":   "redact",
		"text": "the password is " + routerPassword + " and that is all\n",
	})
	if r.Error != nil {
		t.Fatalf("redact: %s", r.Error.Message)
	}
	if strings.Contains(r.Output, routerPassword) {
		t.Errorf("the value survived: %q", r.Output)
	}
	if !strings.Contains(r.Output, token) {
		t.Errorf("output = %q, want the %s token", r.Output, token)
	}
	if len(r.Redactions) == 0 {
		t.Error("the redaction count was not reported")
	}
}

// The op answers about the value set; it must never hand any of it over.
func TestRedactOpReturnsNoValue(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "redact", "text": "nothing to see"})
	if r.Error != nil {
		t.Fatalf("redact: %s", r.Error.Message)
	}
	// Unchanged exactly: anything appended would be the value set describing
	// itself.
	if r.Output != "nothing to see" {
		t.Errorf("output = %q, want it unchanged", r.Output)
	}
}

func TestRedactOpRejectsAMissingText(t *testing.T) {
	h := newHarness(t)
	r := h.call(t, map[string]any{"op": "redact"})
	if r.Error == nil {
		t.Fatal("a redact request with no text was accepted")
	}
}

// The filter shape: what a pipeline uses.
func TestCLIRedactFiltersStdin(t *testing.T) {
	h := newHarness(t)
	cmd := exec.CommandContext(t.Context(), faramirCLI(t), "redact", "--socket", h.brokerSock)
	cmd.Stdin = strings.NewReader("leaked: " + routerPassword + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("faramir redact: %v", err)
	}
	if strings.Contains(string(out), routerPassword) {
		t.Errorf("the value survived the filter: %q", out)
	}
	if !strings.Contains(string(out), token) {
		t.Errorf("stdout = %q, want the %s token", out, token)
	}
}

// The wrapper shape: what the hook rewrites a command into.  Both streams, a
// credential on stderr leaking as far as one on stdout.
func TestCLIRedactWrapsACommandAndCoversBothStreams(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "redact", "--",
		"bash", "-lc", "echo out:"+routerPassword+"; echo err:"+routerPassword+" >&2")
	if strings.Contains(r.stdout, routerPassword) {
		t.Errorf("the value survived: %q", r.stdout)
	}
	if strings.Count(r.stdout, token) != 2 {
		t.Errorf("stdout = %q, want the token on both streams", r.stdout)
	}
}

// A swallowed exit status makes every failure look like a success.
func TestCLIRedactPreservesTheChildExitCode(t *testing.T) {
	h := newHarness(t)
	if r := runCLI(t, h.brokerSock, "redact", "--", "bash", "-lc", "exit 42"); r.code != 42 {
		t.Errorf("exit = %d, want 42", r.code)
	}
	if r := runCLI(t, h.brokerSock, "redact", "--", "bash", "-lc", "exit 0"); r.code != 0 {
		t.Errorf("exit = %d, want 0", r.code)
	}
}

// An unreachable broker means text nobody checked, so none of it is written.
// The command still ran and whatever it changed is changed; what is missing is
// the output, and the status says so rather than letting silence read as a
// command that printed nothing.
func TestCLIRedactWithholdsTheOutputWhenTheBrokerIsGone(t *testing.T) {
	r := runCLI(t, "/nonexistent/broker.sock", "redact", "--", "bash", "-lc", "echo still-ran; exit 7")
	if strings.Contains(r.stdout, "still-ran") {
		t.Errorf("stdout = %q, want nothing the broker never saw", r.stdout)
	}
	// The child's own failure, kept: only its output was withheld.
	if r.code != 7 {
		t.Errorf("exit = %d, want the child's 7", r.code)
	}
	if !strings.Contains(r.stderr, "withheld") {
		t.Errorf("stderr = %q, want it to say the output was withheld", r.stderr)
	}
}

// A child that succeeded still fails the run when its output was withheld,
// there being no way to tell that from a command that printed nothing.
func TestCLIRedactFailsAZeroExitWhenTheOutputWasWithheld(t *testing.T) {
	r := runCLI(t, "/nonexistent/broker.sock", "redact", "--", "bash", "-lc", "echo hi; exit 0")
	if r.code == 0 {
		t.Errorf("exit = 0 with the output withheld; stderr = %q", r.stderr)
	}
	if strings.Contains(r.stdout, "hi") {
		t.Errorf("stdout = %q, want nothing the broker never saw", r.stdout)
	}
}

// One long line must not disable redaction for everything after it: ansible -vvv
// result dicts, minified JSON and lockfiles are all one line.
func TestALineLongerThanAChunkIsStillRedacted(t *testing.T) {
	h := newHarness(t)
	long := strings.Repeat("x", 200_000)
	cmd := exec.CommandContext(t.Context(), faramirCLI(t), "redact", "--socket", h.brokerSock)
	cmd.Stdin = strings.NewReader(
		long + " " + routerPassword + " " + long + "\ntrailing: " + routerPassword + "\n")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("faramir redact: %v", err)
	}
	if strings.Contains(string(out), routerPassword) {
		t.Error("a value survived on or after an over-long line")
	}
	if strings.Count(string(out), token) != 2 {
		t.Errorf("want both values tokenized, got %d", strings.Count(string(out), token))
	}
}

// A brokered command runs where its caller was, not where a config file says.
func TestTheCLIRunsInTheCallersDirectory(t *testing.T) {
	h := newHarness(t)
	elsewhere := t.TempDir()

	cmd := exec.CommandContext(t.Context(), faramirCLI(t), "run", "--socket", h.brokerSock, "--quiet",
		"--", "bash", "-lc", "pwd")
	cmd.Dir = elsewhere
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("faramir run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	// The harness resolves symlinks in its temp dir, so compare against the
	// same resolution.
	if !strings.HasSuffix(got, filepath.Base(elsewhere)) {
		t.Errorf("ran in %q, want the caller's directory %q", got, elsewhere)
	}
}

// -C wins: an explicit directory is the caller being specific.
func TestTheCLIHonoursAnExplicitDirectory(t *testing.T) {
	h := newHarness(t)
	elsewhere, explicit := t.TempDir(), t.TempDir()

	cmd := exec.CommandContext(t.Context(), faramirCLI(t), "run", "--socket", h.brokerSock, "--quiet",
		"-C", explicit, "--", "bash", "-lc", "pwd")
	cmd.Dir = elsewhere
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("faramir run: %v", err)
	}
	if got := strings.TrimSpace(string(out)); !strings.HasSuffix(got, filepath.Base(explicit)) {
		t.Errorf("ran in %q, want %q", got, explicit)
	}
}
