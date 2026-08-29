package main

import (
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/escalation"
)

// The PAM helper's exit status is the whole authentication: zero authenticates
// the sudo, anything else refuses it. So every check here is about a path that
// must NOT return zero, and the socket it would ask is one nothing is listening
// on: a helper that reached the broker at all would already have got past the
// guard being tested.
const noBroker = "/nonexistent/faramir-pam-escalate-test.sock"

func pamEscalate(t *testing.T, env map[string]string, args ...string) int {
	t.Helper()
	for name, value := range env {
		t.Setenv(name, value)
	}
	return runPamEscalateCommand(args)
}

// The helper asks the installed broker and nothing else. It runs inside the
// sudo of the account it decides about, and pam_exec hands the module that
// account's environment: a socket read from there is one the caller could have
// bound itself, answering "approved" to everything.
func TestThePamHelperTakesNoSocketFromTheEnvironment(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", noBroker)
	if got := pamSocket(); got != defaultSocket {
		t.Errorf("the helper would ask %q: the environment moved the broker it "+
			"asks, and the caller owns that environment", got)
	}
}

// pam_exec runs a module for every stage of the stack it is named in. This one
// decides authentication, so a service file that put it on `account` or
// `session`, where a non-zero status means something else entirely, must not be
// able to authenticate anything.
func TestOnlyTheAuthStageDecidesAnything(t *testing.T) {
	for _, stage := range []string{"account", "session", "password", ""} {
		t.Run(stage, func(t *testing.T) {
			env := map[string]string{"PAM_TYPE": stage, "PAM_USER": "faramir-exec"}
			if code := pamEscalate(t, env, "--account", "faramir-exec"); code == 0 {
				t.Errorf("PAM_TYPE=%q authenticated a sudo", stage)
			}
		})
	}
}

// The service is for one account. A sudoers entry pointing another account's
// sudo at it, or the file being copied to /etc/pam.d/sudo where every account
// reads it, is a service deciding calls it was not written for.
func TestTheServiceAuthenticatesOneAccount(t *testing.T) {
	env := map[string]string{"PAM_TYPE": "auth", "PAM_USER": "root"}
	if code := pamEscalate(t, env, "--account", "faramir-exec"); code == 0 {
		t.Error("a call for root was authenticated by faramir-exec's service")
	}
}

// A sudo that no brokered command is above is somebody typing `sudo` as the
// executor's account. There is no run to approve and nobody to ask about, so
// it is refused without the broker being contacted at all.
func TestASudoUnderNoBrokeredCommandIsRefused(t *testing.T) {
	// The walk, said rather than performed: this process's ancestors are whatever
	// ran `go test`, and the socket the helper asks is the compiled-in one, so
	// without this the call reaches whatever broker the host is running and passes
	// on a stranger's answer instead of on the branch under test.
	original := ancestryOf
	ancestryOf = func(int) []int { return nil }
	t.Cleanup(func() { ancestryOf = original })

	env := map[string]string{"PAM_TYPE": "auth", "PAM_USER": "faramir-exec"}
	if code := pamEscalate(t, env, "--account", "faramir-exec"); code == 0 {
		t.Error("a sudo with no brokered command above it was authenticated")
	}
}

// An unreachable broker is a refusal, not a pass. This is the shape of every
// failure below the guards: the daemon being down, the socket being gone, the
// question expiring. A helper that failed open here would make stopping the
// broker the way to sudo.
//
// Asked of askBrokerToApprove rather than through runPamEscalateCommand, so the subject
// is the answer to an unreachable broker rather than the walk above it.
func TestAnUnreachableBrokerRefuses(t *testing.T) {
	approved, _, err := askBrokerToApprove(noBroker, []int{os.Getpid()})
	if err == nil {
		t.Fatal("a broker that is not there answered")
	}
	if approved {
		t.Error("an unreachable broker authenticated a sudo")
	}
}

// Neither a usage error nor a help flag authenticates anything: PAM reads the
// status, so both have to be non-zero. The help flag is the trap: the flag
// parser returns 0 for it, which is success for an ordinary command and an auth
// pass here, so this helper forces it non-zero.
func TestNoFlagPathAuthenticates(t *testing.T) {
	t.Setenv("PAM_TYPE", "auth")
	for _, args := range [][]string{{"--no-such-flag"}, {"--help"}, {"-h"}} {
		if code := runPamEscalateCommand(args); code == 0 {
			t.Errorf("runPamEscalateCommand(%v) returned 0: a flag-parsing exit authenticated a sudo", args)
		}
	}
}

// The ancestry is how the helper says which brokered command is asking: PAM
// passes a module none of the caller's environment, and it does not have to,
// this running as root with the process tree in /proc.
//
// Run by re-execing this test binary underneath two shells, which is the only
// way to give the real walk real ancestors: a call made here would start at the
// test runner, whose parents are whatever ran `go test`.
const walkProbeEnv = "FARAMIR_TEST_PAM_WALK"

func TestMain(m *testing.M) {
	if os.Getenv(walkProbeEnv) != "" {
		for _, pid := range escalation.Ancestry(os.Getppid()) {
			fmt.Println(pid)
		}
		os.Exit(0)
	}
	os.Exit(m.Run())
}

// walk runs the probe under `sh -c 'sh -c …'`: three live processes, no `exec`
// in the chain, which would collapse them into one and leave nothing to walk.
// It reports what findToken saw from the bottom.
func walk(t *testing.T, environ []string) string {
	t.Helper()
	if _, err := os.Stat("/proc/self/environ"); err != nil {
		t.Skip("no /proc; the walk cannot be checked here")
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(t.Context(), "/bin/sh", "-c", "/bin/sh -c '\""+self+"\"'")
	command.Env = append([]string{walkProbeEnv + "=1"}, environ...)
	// stdout only, kept apart from stderr: the probe prints the ancestry to stdout,
	// and a coverage-instrumented re-exec of the test binary (as CI builds it)
	// writes "warning: GOCOVERDIR not set" to stderr. CombinedOutput would fold
	// that into the token; here it stays in stderr, reported only if the run fails.
	var stderr strings.Builder
	command.Stderr = &stderr
	out, err := command.Output()
	if err != nil {
		t.Fatalf("%v: %s", err, stderr.String())
	}
	return strings.TrimSpace(string(out))
}

// The walk crosses the two shells between the probe and the test binary, which
// stand in for the shell and the sudo that sit between a brokered command and
// this helper. What the executor forked is somewhere above, so a walk that
// stopped early would leave a real escalation unattributable.
func TestTheAncestryReachesPastTheProcessesBetween(t *testing.T) {
	lines := strings.Fields(walk(t, []string{"PATH=/usr/bin:/bin"}))
	if len(lines) < 3 {
		t.Fatalf("the walk reported %d process(es) (%v); the two shells and what "+
			"started them are all above the probe", len(lines), lines)
	}
	seen := map[string]bool{}
	for _, pid := range lines {
		if pid == "" || pid == "0" || pid == "1" {
			t.Errorf("%q is not a process a run could have forked", pid)
		}
		if seen[pid] {
			t.Errorf("pid %s was reported twice: the walk is going in a circle", pid)
		}
		seen[pid] = true
	}
}
