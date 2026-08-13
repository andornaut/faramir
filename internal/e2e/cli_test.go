package e2e

import (
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
)

var (
	cliOnce sync.Once
	cliPath string
	cliErr  error
)

// faramirCLI builds the real CLI once per run.  The flag surface is a contract
// with `faramir doctor`, which drives the deployed binary as another uid, so a
// missing flag turns every boundary finding into "could not run one".
func faramirCLI(t *testing.T) string {
	t.Helper()
	cliOnce.Do(func() {
		dir, err := os.MkdirTemp("", "faramir-cli-")
		if err != nil {
			cliErr = err
			return
		}
		out := filepath.Join(dir, "faramir")
		cmd := exec.Command("go", "build", "-o", out, "github.com/andornaut/faramir/cmd/faramir")
		if combined, err := cmd.CombinedOutput(); err != nil {
			cliErr = err
			t.Logf("building the CLI: %s", combined)
			return
		}
		cliPath = out
	})
	// Fatal rather than skipped: this is the repository's own binary, so a build
	// that fails is a bug here.  Skipped instead, it takes every test below that
	// drives the CLI with it and the package reports green having run none.
	if cliErr != nil {
		t.Fatalf("could not build the CLI: %v", cliErr)
	}
	return cliPath
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// runCLI names the socket after the verb: --socket is registered per
// subcommand, not globally.
func runCLI(t *testing.T, sock string, args ...string) cliResult {
	t.Helper()
	return runCLIEnv(t, nil, append([]string{args[0], "--socket", sock}, args[1:]...)...)
}

// runCLIEnv is the CLI run without a socket flag, the environment named
// outright.
func runCLIEnv(t *testing.T, env []string, args ...string) cliResult {
	t.Helper()
	cmd := exec.Command(faramirCLI(t), args...)
	if env != nil {
		cmd.Env = append(os.Environ(), env...)
	}
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	_ = cmd.Run()
	return cliResult{stdout: out.String(), stderr: errBuf.String(), code: cmd.ProcessState.ExitCode()}
}

// The exact invocation doctor uses for every brokered check.
func TestCLIAcceptsTheDoctorInvocation(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "run", "--quiet",
		"--env", "ROUTER_PW=secret://home/router/admin", "--", "printenv", "ROUTER_PW")
	if r.code != 0 {
		t.Fatalf("exit = %d\nstdout=%q\nstderr=%q", r.code, r.stdout, r.stderr)
	}
	if !strings.Contains(r.stdout, token) {
		t.Errorf("stdout = %q", r.stdout)
	}
	if strings.Contains(r.stdout, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED: %q", r.stdout)
	}
	// --quiet suppresses the summary, the findings matching on the command's
	// own output.
	if strings.Contains(r.stderr, "redacted") {
		t.Errorf("--quiet did not suppress the summary: %q", r.stderr)
	}
}

// The summary goes to stderr, with log_id even when nothing was redacted: it is
// how the agent points the operator at a log.
func TestCLISummaryReportsLogIDWithoutRedactions(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "run", "--", "printenv", "PATH")
	if r.code != 0 {
		t.Fatalf("exit = %d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stderr, "log_id=") {
		t.Errorf("no log_id in the summary: %q", r.stderr)
	}
}

func TestCLIShorthandFlags(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "run", "-C", h.dir, "-t", "20", "--", "printenv", "PATH")
	if r.code != 0 {
		t.Fatalf("-C/-t were not accepted: exit = %d stderr=%q", r.code, r.stderr)
	}
}

func TestCLIJSONPrintsTheRawResponse(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "status", "--json")
	if r.code != 0 {
		t.Fatalf("exit = %d stderr=%q", r.code, r.stderr)
	}
	for _, want := range []string{`"exit_code"`, `"output"`, `"redactions"`} {
		if !strings.Contains(r.stdout, want) {
			t.Errorf("--json output is missing %s: %q", want, r.stdout)
		}
	}
}

// EX_UNAVAILABLE, so a caller can tell "not running" from "the command
// failed".
func TestCLIUnavailableBrokerIsEX_UNAVAILABLE(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.sock")
	r := runCLI(t, missing, "status")
	if r.code != 69 {
		t.Errorf("exit = %d, want 69 (EX_UNAVAILABLE); stderr=%q", r.code, r.stderr)
	}
}

// The child's exit code is the CLI's exit code, so a caller can branch on it.
func TestCLIPropagatesTheChildExitCode(t *testing.T) {
	h := newHarness(t)
	for _, want := range []int{0, 3, 42} {
		r := runCLI(t, h.brokerSock, "run", "--quiet", "--",
			"bash", "-lc", "exit "+strconv.Itoa(want))
		if r.code != want {
			t.Errorf("exit = %d, want %d (stderr=%q)", r.code, want, r.stderr)
		}
	}
}

func TestCLIListSecretsAndStatus(t *testing.T) {
	h := newHarness(t)
	if r := runCLI(t, h.brokerSock, "list-secrets"); r.code != 0 ||
		!strings.Contains(r.stdout, "secret://home/router/admin") {
		t.Errorf("list-secrets: exit=%d stdout=%q", r.code, r.stdout)
	}
	if r := runCLI(t, h.brokerSock, "status"); r.code != 0 ||
		!strings.Contains(r.stdout, "count") {
		t.Errorf("status: exit=%d stdout=%q", r.code, r.stdout)
	}
}

// --help is a request that succeeded; non-zero makes the CLI unusable under
// "set -e".
func TestCLIHelpExitsZeroOnStdout(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"run", "--help"}, {"status", "--help"}} {
		r := runCLIEnv(t, nil, args...)
		if r.code != 0 {
			t.Errorf("%v: exit = %d, want 0", args, r.code)
		}
		if r.stdout == "" {
			t.Errorf("%v: help went nowhere (stderr=%q)", args, r.stderr)
		}
	}
}

// A bad flag belongs on stderr, with exit 2.
func TestCLIBadFlagIsAUsageErrorOnStderr(t *testing.T) {
	r := runCLIEnv(t, nil, "run", "--not-a-flag")
	if r.code != 2 {
		t.Errorf("exit = %d, want 2", r.code)
	}
	if r.stdout != "" {
		t.Errorf("a usage error went to stdout: %q", r.stdout)
	}
	if !strings.Contains(r.stderr, "not-a-flag") {
		t.Errorf("stderr does not name the flag: %q", r.stderr)
	}
}

// FARAMIR_SOCKET moves every subcommand at once.
func TestCLIHonoursFaramirSocketEnv(t *testing.T) {
	h := newHarness(t)
	r := runCLIEnv(t, []string{"FARAMIR_SOCKET=" + h.brokerSock}, "list-secrets")
	if r.code != 0 {
		t.Fatalf("exit = %d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, "secret://home/router/admin") {
		t.Errorf("stdout = %q", r.stdout)
	}
}
