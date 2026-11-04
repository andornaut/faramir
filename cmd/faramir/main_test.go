package main

import (
	"os/user"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/testio"
)

// A usage error a command returns once it is running exits 2 and is said once,
// on one line, under the command's label: the root silences what a RunE
// returns, so run is what prints it. read-link refuses a missing --path before
// it reads anything.
func TestAUsageErrorFromARunningCommandIsOneLine(t *testing.T) {
	said, code := testio.CaptureStderr(t, func() int { return run([]string{"read-link", "--type", "env"}) })
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage)", code)
	}
	if want := "faramir read-link: --path and --type are required\n"; said != want {
		t.Errorf("stderr = %q, want %q", said, want)
	}
}

// One refused before the command runs is cobra's to print, and run does not
// print it a second time.
func TestAUsageErrorFromArgumentValidationIsSaidOnce(t *testing.T) {
	said, code := testio.CaptureStderr(t, func() int { return run([]string{"version", "extra"}) })
	if code != 2 {
		t.Errorf("exit = %d, want 2 (usage)", code)
	}
	if n := strings.Count(said, "takes no arguments"); n != 1 {
		t.Errorf("the refusal is said %d times, want once: %q", n, said)
	}
}

func TestTheSocketEnvVarOverridesTheDefault(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", "/tmp/custom.sock")
	if got := socketDefault(); got != "/tmp/custom.sock" {
		t.Errorf("got %q, want the value of FARAMIR_SOCKET", got)
	}
}

func TestAnEmptySocketEnvVarFallsBackToTheDefault(t *testing.T) {
	t.Setenv("FARAMIR_SOCKET", "")
	if got := socketDefault(); got == "" {
		t.Error("an empty FARAMIR_SOCKET left no socket path at all")
	}
}

// The account that works in the tree, in resolution order. The flag is the
// only way to name one where neither $FARAMIR_OPERATOR nor SUDO_USER is set.
func TestOperatorNameResolution(t *testing.T) {
	// The last candidate, and so the answer when nothing else names one.
	current, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	// Unless the caller is one this refuses at every position, root or a faramir
	// account: run that way with nothing set, no operator is named rather than
	// one claimed.
	refused := notTheOperator()
	fallback := current.Username
	if refused[fallback] {
		fallback = ""
	}
	for _, tc := range []struct{ name, flag, operator, sudoUser, want string }{
		{"the flag wins", "flagged", "brokered", "sudo", "flagged"},
		{"SUDO_USER when that is all there is", "", "", "sudo", "sudo"},
		{"root is not an answer", "root", "", "sudo", "sudo"},
		// A brokered command's sudo sets SUDO_USER to the executor, whose home holds
		// none of the operator's configuration. $FARAMIR_OPERATOR is the marker that
		// says so, written by the broker from the live config and carried to root by
		// the grant's env_file, so it outranks what sudo filled in.
		{"the broker's marker outranks SUDO_USER", "", "brokered", "sudo", "brokered"},
		{"and names the operator where sudo named the executor", "",
			"brokered", hostlayout.DefaultExecUser, "brokered"},
		// Without the marker there is nothing to correct SUDO_USER with, so the
		// service account falls through rather than being taken for a person: an
		// enrolment that believed it would chown a checkout to an account holding
		// nothing.
		{"a faramir account in SUDO_USER is not an answer", "", "",
			hostlayout.DefaultExecUser, fallback},
		{"nor is the broker's own", "", "", hostlayout.DefaultBrokerUser, fallback},
		{"nor the keeper's", "", "", hostlayout.DefaultKeeperUser, fallback},
		// Nobody named, so the caller is who this is about: doctor run by hand would
		// otherwise report them as an account nothing created.
		{"nothing at all falls back to the caller", "", "", "", fallback},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(protocol.OperatorEnv, tc.operator)
			t.Setenv("SUDO_USER", tc.sudoUser)
			if got := operatorName(refused, tc.flag); got != tc.want {
				t.Errorf("operatorName(%q) = %q, want %q", tc.flag, got, tc.want)
			}
		})
	}
}
