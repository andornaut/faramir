package e2e

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --env-file is how a command that needs a dozen credentials stops needing a
// dozen flags at every call site.  The file holds refs, never values.
func TestCLIEnvFileInjectsTheNamedRefs(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "refs.env")
	body := "# the router\nROUTER_PW=secret://home/router/admin\n\n"
	if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, h.brokerSock, "run", "--quiet", "--env-file", file,
		"--", "printenv", "ROUTER_PW")
	if r.code != 0 {
		t.Fatalf("exit = %d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, token) {
		t.Errorf("the ref was not injected: %q", r.stdout)
	}
	if strings.Contains(r.stdout, routerPassword) {
		t.Errorf("PLAINTEXT LEAKED: %q", r.stdout)
	}
}

// A literal value in the file is the mistake worth catching by name: it would
// otherwise be rejected by the broker with no idea which line it came from.
func TestCLIEnvFileRejectsALiteralValue(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "refs.env")
	if err := os.WriteFile(file, []byte("ROUTER_PW=hunter2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, h.brokerSock, "run", "--env-file", file, "--", "true")
	if r.code != 2 {
		t.Errorf("exit = %d, want 2", r.code)
	}
	for _, want := range []string{"refs.env:1", "secret://"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("stderr does not name %q: %q", want, r.stderr)
		}
	}
}

// An explicit --env wins, so a wrapper script can override one entry without
// rewriting the file.
func TestCLIEnvFlagOverridesTheFile(t *testing.T) {
	h := newHarness(t)
	file := filepath.Join(t.TempDir(), "refs.env")
	if err := os.WriteFile(file, []byte("ROUTER_PW=secret://nope\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := runCLI(t, h.brokerSock, "run", "--quiet", "--env-file", file,
		"--env", "ROUTER_PW=secret://home/router/admin", "--", "printenv", "ROUTER_PW")
	if r.code != 0 {
		t.Fatalf("exit = %d stderr=%q", r.code, r.stderr)
	}
	if !strings.Contains(r.stdout, token) {
		t.Errorf("the flag did not override the file: %q %q", r.stdout, r.stderr)
	}
}
