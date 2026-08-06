// Turning cmd[0] into the path the executor runs.
//
// There is no allowlist left to test.  What is left is the part that has to be
// right for correctness rather than for policy: resolving a name to the file
// the child would itself have run, since getting that wrong means running a
// different file rather than refusing one.
package resolve

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func cfgWithPath(path string) config.ExecConfig {
	return config.ExecConfig{DefaultCwd: "/", BaseEnv: map[string]string{"PATH": path}}
}

// -- bare names: looked up on the PATH the child will actually get -----------

func TestBareNameResolvesOnTheConfiguredPath(t *testing.T) {
	got, err := Program("sh", "/", cfgWithPath("/usr/bin:/bin"))
	if err != nil {
		t.Fatal(err)
	}
	want := realpath("/bin/sh")
	if got != want {
		t.Errorf("Program(sh) = %q, want %q", got, want)
	}
}

func TestTheBrokersOwnPathIsNotConsulted(t *testing.T) {
	// The process PATH almost certainly contains /bin; base_env does not.
	_, err := Program("sh", "/", cfgWithPath("/nonexistent"))
	if err == nil {
		t.Fatal("resolved against the broker's own PATH")
	}
	if !strings.Contains(err.Error(), "not found on the broker's PATH") {
		t.Errorf("message = %q", err.Error())
	}
}

// The one failure an operator will actually hit, so it has to be
// self-correcting rather than merely true.
func TestTheErrorSaysWhereToPutAVenv(t *testing.T) {
	_, err := Program("ansible-playbook", "/", cfgWithPath("/nonexistent"))
	if err == nil {
		t.Fatal("expected a failure")
	}
	for _, want := range []string{"base_env", "venv"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("message does not mention %q: %q", want, err.Error())
		}
	}
}

// -- explicit paths ---------------------------------------------------------

func scriptFixture(t *testing.T) (dir, script string, cfg config.ExecConfig) {
	t.Helper()
	dir = t.TempDir()
	script = filepath.Join(dir, "deploy.sh")
	if err := os.WriteFile(script, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, script, config.ExecConfig{DefaultCwd: dir}
}

// No allowed_bin_dirs any more: a script in the working tree is exactly the
// thing an operator wants to run, and it never lived in /usr/bin.
func TestAnAbsolutePathAnywhereIsFine(t *testing.T) {
	dir, script, cfg := scriptFixture(t)
	got, err := Program(script, dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != realpath(script) {
		t.Errorf("got %q, want %q", got, realpath(script))
	}
}

// Not the broker's own working directory: that would silently execute a
// different file of the same name.
func TestARelativePathResolvesAgainstTheRequestCwd(t *testing.T) {
	dir, script, cfg := scriptFixture(t)
	got, err := Program("./deploy.sh", dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != realpath(script) {
		t.Errorf("got %q, want %q", got, realpath(script))
	}
}

func TestADifferentCwdDoesNotFindIt(t *testing.T) {
	_, _, cfg := scriptFixture(t)
	if _, err := Program("./deploy.sh", "/usr", cfg); err == nil {
		t.Fatal("resolved from the wrong cwd")
	}
}

func TestAMissingProgramIsNamed(t *testing.T) {
	dir, _, cfg := scriptFixture(t)
	_, err := Program(filepath.Join(dir, "nope"), dir, cfg)
	if err == nil {
		t.Fatal("expected a failure")
	}
	if !strings.Contains(err.Error(), "no such program") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestANonExecutableFileIsRefused(t *testing.T) {
	dir, _, cfg := scriptFixture(t)
	plain := filepath.Join(dir, "notes.txt")
	if err := os.WriteFile(plain, []byte("hello\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_, err := Program(plain, dir, cfg)
	if err == nil {
		t.Fatal("a non-executable file was accepted")
	}
	if !strings.Contains(err.Error(), "not executable") {
		t.Errorf("message = %q", err.Error())
	}
}

func TestSymlinksAreResolved(t *testing.T) {
	dir, script, cfg := scriptFixture(t)
	link := filepath.Join(dir, "link.sh")
	if err := os.Symlink(script, link); err != nil {
		t.Fatal(err)
	}
	got, err := Program(link, dir, cfg)
	if err != nil {
		t.Fatal(err)
	}
	if got != realpath(script) {
		t.Errorf("got %q, want %q", got, realpath(script))
	}
}

func TestEmptyIsRefused(t *testing.T) {
	dir, _, cfg := scriptFixture(t)
	if _, err := Program("", dir, cfg); err == nil {
		t.Fatal("an empty command was accepted")
	}
}

// An absolute cmd[0] must not be joined onto cwd.  Go's filepath.Join would
// produce "/cwd/bin/sh"; the absolute path has to win outright, because that
// is what the child's own exec would do with it.
func TestAnAbsolutePathIgnoresTheCwd(t *testing.T) {
	got, err := Program("/bin/sh", "/tmp", config.ExecConfig{DefaultCwd: "/tmp"})
	if err != nil {
		t.Fatal(err)
	}
	if got != realpath("/bin/sh") {
		t.Errorf("got %q, want %q", got, realpath("/bin/sh"))
	}
}
