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
// with tests/verify.sh, which drives the deployed binary, so it is exercised
// here rather than assumed: a missing flag makes the whole verification matrix
// exit 2 on its first brokered check.
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
	if cliErr != nil {
		t.Skipf("could not build the CLI: %v", cliErr)
	}
	return cliPath
}

type cliResult struct {
	stdout, stderr string
	code           int
}

// --socket belongs to the subcommand, not the program: it is registered on
// every subparser rather than globally, so it goes after the verb.
func runCLI(t *testing.T, sock string, args ...string) cliResult {
	t.Helper()
	full := append([]string{args[0], "--socket", sock}, args[1:]...)
	cmd := exec.Command(faramirCLI(t), full...)
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	_ = cmd.Run()
	return cliResult{stdout: out.String(), stderr: errBuf.String(), code: cmd.ProcessState.ExitCode()}
}

// The exact invocation tests/verify.sh:36 uses for every brokered check.
func TestCLIAcceptsVerifyShInvocation(t *testing.T) {
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
	// --quiet suppresses the summary, which is why verify.sh passes it: the
	// checks match on the command's own output.
	if strings.Contains(r.stderr, "redacted") {
		t.Errorf("--quiet did not suppress the summary: %q", r.stderr)
	}
}

// Without --quiet the summary goes to stderr, and log_id is reported even when
// nothing was redacted: it is how the agent points the operator at a log.
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

// A broker that is not there is EX_UNAVAILABLE, not a generic failure, so a
// caller can tell "not running" from "the command failed".
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
		!strings.Contains(r.stdout, "ref_count") {
		t.Errorf("status: exit=%d stdout=%q", r.code, r.stdout)
	}
}

// Asking for help is a request that succeeded.  Exiting non-zero on --help
// makes the CLI unusable from any script with "set -e".
func TestCLIHelpExitsZeroOnStdout(t *testing.T) {
	for _, args := range [][]string{{"--help"}, {"run", "--help"}, {"status", "--help"}} {
		cmd := exec.Command(faramirCLI(t), args...)
		var out, errBuf strings.Builder
		cmd.Stdout, cmd.Stderr = &out, &errBuf
		_ = cmd.Run()
		if code := cmd.ProcessState.ExitCode(); code != 0 {
			t.Errorf("%v: exit = %d, want 0", args, code)
		}
		if out.Len() == 0 {
			t.Errorf("%v: help went nowhere (stderr=%q)", args, errBuf.String())
		}
	}
}

// A bad flag is the opposite case: it belongs on stderr, with exit 2.
func TestCLIBadFlagIsAUsageErrorOnStderr(t *testing.T) {
	cmd := exec.Command(faramirCLI(t), "run", "--not-a-flag")
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	_ = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 2 {
		t.Errorf("exit = %d, want 2", code)
	}
	if out.Len() != 0 {
		t.Errorf("a usage error went to stdout: %q", out.String())
	}
	if !strings.Contains(errBuf.String(), "not-a-flag") {
		t.Errorf("stderr does not name the flag: %q", errBuf.String())
	}
}

// FARAMIR_SOCKET moves every subcommand at once.  faramir-mcp already honours
// it and tests/verify.sh sets it, so the CLI has to agree.
func TestCLIHonoursFaramirSocketEnv(t *testing.T) {
	h := newHarness(t)
	cmd := exec.Command(faramirCLI(t), "list-secrets")
	cmd.Env = append(os.Environ(), "FARAMIR_SOCKET="+h.brokerSock)
	var out, errBuf strings.Builder
	cmd.Stdout, cmd.Stderr = &out, &errBuf
	_ = cmd.Run()
	if code := cmd.ProcessState.ExitCode(); code != 0 {
		t.Fatalf("exit = %d stderr=%q", code, errBuf.String())
	}
	if !strings.Contains(out.String(), "secret://home/router/admin") {
		t.Errorf("stdout = %q", out.String())
	}
}

// A removed op must not be silently accepted by the CLI either.
func TestCLIHasNoSyncSubcommand(t *testing.T) {
	h := newHarness(t)
	r := runCLI(t, h.brokerSock, "sync")
	if r.code == 0 {
		t.Error("the removed sync subcommand still runs")
	}
	if !strings.Contains(r.stderr, "unknown command") {
		t.Errorf("stderr = %q", r.stderr)
	}
}
