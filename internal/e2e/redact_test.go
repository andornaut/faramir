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
	payload, _ := json.Marshal(map[string]any{
		"tool_name":  "Bash",
		"tool_input": map[string]any{"command": command},
	})
	// The hook is `faramir guard`, the same binary the settings file registers.
	hook := exec.Command(cliPath, "guard")
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

// The rewrite has to survive being run for real, in one shell, twice: that is
// how the agent's Bash tool works, and it is where a wrapper that uses a
// subshell or a pipeline silently loses the session's state.
func TestTheRewrittenCommandRedactsAndKeepsShellState(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)

	first := guardRewrite(t, cli, "cd /var; export FR_KEPT=yes; echo leaked:"+routerPassword)
	second := guardRewrite(t, cli, `echo "pwd=$PWD kept=${FR_KEPT:-lost}"`)

	session := exec.Command("bash", "-c", first+"\n"+second+"\n")
	session.Dir = "/tmp"
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli)
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
	// The state the first command set has to reach the second one.
	if !strings.Contains(got, "pwd=/var") {
		t.Errorf("output = %q, want cd to have persisted to the next command", got)
	}
	if !strings.Contains(got, "kept=yes") {
		t.Errorf("output = %q, want export to have persisted to the next command", got)
	}
}

// runWrapped runs a rewritten command the way the agent's shell would, with
// stdout and stderr kept apart: what the agent reads is stdout, and the whole
// point of failing closed is that unredacted text never reaches it.
func runWrapped(t *testing.T, rewritten string, env ...string) (stdout, stderr string, code int) {
	t.Helper()
	session := exec.Command("bash", "-c", rewritten)
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

// Output that could not be redacted is withheld rather than shown.  A broker
// that is not there is the ordinary way this happens, and printing the raw
// output then would put into the agent's context exactly what the wrapper
// exists to keep out of it.
func TestTheWrapperWithholdsOutputItCouldNotRedact(t *testing.T) {
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo leaked:"+routerPassword)

	stdout, stderr, code := runWrapped(t, rewritten,
		"FARAMIR_SOCKET="+filepath.Join(t.TempDir(), "absent.sock"), "FARAMIR_CLI="+cli)

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
	// nothing, which is how a broken redactor goes unnoticed.
	if code == 0 {
		t.Error("a withheld output was reported as a clean success")
	}
}

// With nowhere to capture output there is nothing to redact, so the command
// does not run at all.  Running it would send its output straight through.
func TestTheWrapperDoesNotRunACommandItCannotCapture(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)
	marker := filepath.Join(t.TempDir(), "ran")
	rewritten := guardRewrite(t, cli, "echo "+routerPassword+" > "+marker)

	// mktemp is what the wrapper has to have; shadow it rather than simulate a
	// full /dev/shm.
	shim := t.TempDir()
	if err := os.WriteFile(filepath.Join(shim, "mktemp"),
		[]byte("#!/bin/sh\nexit 1\n"), 0o755); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, code := runWrapped(t, rewritten, "PATH="+shim+":"+os.Getenv("PATH"),
		"FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli)

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

// A failing command has to keep failing, or every check an agent runs reads as
// a pass.
func TestTheRewrittenCommandKeepsTheExitCode(t *testing.T) {
	h := newHarness(t)
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo before; (exit 33)")

	session := exec.Command("bash", "-c", rewritten)
	session.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock, "FARAMIR_CLI="+cli)
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

// The temporary file the wrapper writes must not be left behind holding
// unredacted output.
func TestTheRewriteLeavesNoTemporaryFile(t *testing.T) {
	h := newHarness(t)
	dir := t.TempDir()
	cli := faramirCLI(t)
	rewritten := guardRewrite(t, cli, "echo "+routerPassword)

	session := exec.Command("bash", "-c", rewritten)
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

// The redact op is what gives a session outside the broker's uid the same
// redaction a brokered command gets.  Text in, tokens out.
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
	// Unchanged exactly: anything the redactor appended would be the value set
	// describing itself in a response about text that never held one.
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
	cmd := exec.Command(faramirCLI(t), "redact", "--socket", h.brokerSock)
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

// The wrapper shape: what the PreToolUse hook rewrites a command into.  Both
// streams are covered, because a command that prints a credential to stderr
// leaks exactly as far as one that prints it to stdout.
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

// A wrapper that swallows the child's exit status would make every failure look
// like a success to whatever reads it.
func TestCLIRedactPreservesTheChildExitCode(t *testing.T) {
	h := newHarness(t)
	if r := runCLI(t, h.brokerSock, "redact", "--", "bash", "-lc", "exit 42"); r.code != 42 {
		t.Errorf("exit = %d, want 42", r.code)
	}
	if r := runCLI(t, h.brokerSock, "redact", "--", "bash", "-lc", "exit 0"); r.code != 0 {
		t.Errorf("exit = %d, want 0", r.code)
	}
}

// An unreachable broker must not break the command it wraps.  A wrapper that
// fails closed here is a wrapper that gets removed, and a removed wrapper
// redacts nothing at all.
func TestCLIRedactPassesOutputThroughWhenTheBrokerIsGone(t *testing.T) {
	r := runCLI(t, "/nonexistent/broker.sock", "redact", "--", "bash", "-lc", "echo still-ran; exit 7")
	if !strings.Contains(r.stdout, "still-ran") {
		t.Errorf("stdout = %q, want the command's own output", r.stdout)
	}
	if r.code != 7 {
		t.Errorf("exit = %d, want the child's 7", r.code)
	}
	if !strings.Contains(r.stderr, "unredacted") {
		t.Errorf("stderr = %q, want it to say the output was not redacted", r.stderr)
	}
}

// One line longer than a chunk must not disable redaction for everything after
// it.  ansible -vvv result dicts, minified JSON and lockfiles are all one long
// line, and they are exactly the output most likely to carry a credential.
func TestALineLongerThanAChunkIsStillRedacted(t *testing.T) {
	h := newHarness(t)
	long := strings.Repeat("x", 200_000)
	cmd := exec.Command(faramirCLI(t), "redact", "--socket", h.brokerSock)
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
// Without this the same "faramir run make" builds a different checkout
// depending on a setting nobody looked at.
func TestTheCLIRunsInTheCallersDirectory(t *testing.T) {
	h := newHarness(t)
	elsewhere := t.TempDir()

	cmd := exec.Command(faramirCLI(t), "run", "--socket", h.brokerSock, "--quiet",
		"--", "bash", "-lc", "pwd")
	cmd.Dir = elsewhere
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("faramir run: %v", err)
	}
	got := strings.TrimSpace(string(out))
	// The harness resolves symlinks in its temp dir, so compare what the shell
	// reports against the same resolution rather than the raw path.
	if !strings.HasSuffix(got, filepath.Base(elsewhere)) {
		t.Errorf("ran in %q, want the caller's directory %q", got, elsewhere)
	}
}

// -C still wins: an explicit directory is the caller being specific.
func TestTheCLIHonoursAnExplicitDirectory(t *testing.T) {
	h := newHarness(t)
	elsewhere, explicit := t.TempDir(), t.TempDir()

	cmd := exec.Command(faramirCLI(t), "run", "--socket", h.brokerSock, "--quiet",
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
