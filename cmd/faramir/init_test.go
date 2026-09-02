package main

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/protocol"
)

// writeAgentUserConfig is a config recording one operator, for the resolution a
// command that rewrites the config uses.
func writeAgentUserConfig(t *testing.T, agentUser string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.toml")
	body := "[server]\n"
	if agentUser != "" {
		body += "agent_user = \"" + agentUser + "\"\n"
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// What `block add` and `link add` resolve the operator to. They rewrite the whole
// config, so one that resolved it afresh would rename the host's owner as a side
// effect: a brokered `sudo faramir block add` has SUDO_USER set to the executor,
// and recording that account renders every path rule against its home.
func TestARewriteKeepsTheRecordedOperator(t *testing.T) {
	for _, tc := range []struct{ name, recorded, operator, sudoUser, want string }{
		{"the recorded operator wins over SUDO_USER", "op", "", "someoneelse", "op"},
		// The case this exists for.
		{"and over the executor a brokered sudo names", "op", "", hostlayout.DefaultExecUser, "op"},
		// Ahead of the marker too: the marker says who the host belongs to, which is
		// what the config already recorded, so they agree unless the config is what
		// went wrong, and this command is not the one that repairs it.
		{"and over the broker's own marker", "op", "brokered", hostlayout.DefaultExecUser, "op"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(protocol.OperatorEnv, tc.operator)
			t.Setenv("SUDO_USER", tc.sudoUser)
			got := recordedOperator(writeAgentUserConfig(t, tc.recorded))
			if got != tc.want {
				t.Errorf("recordedOperator = %q, want %q", got, tc.want)
			}
		})
	}
}

// An install whose config records nothing is one `init` has not finished, so
// there is no recorded answer to prefer and this resolves as everything else
// does. Held here because the fallback is what a host mid-provision depends on.
func TestARewriteFallsBackWhereNothingIsRecorded(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "sudo")
	if got := recordedOperator(writeAgentUserConfig(t, "")); got != "sudo" {
		t.Errorf("recordedOperator = %q, want the resolved %q", got, "sudo")
	}
}

// A config recording one of faramir's own accounts is the damage this change
// prevents, and a host that already carries it must not have it preserved.
func TestARewriteDoesNotKeepAServiceAccountAsTheOperator(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "op")
	if got := recordedOperator(writeAgentUserConfig(t, hostlayout.DefaultExecUser)); got != "op" {
		t.Errorf("recordedOperator = %q, want %q: a recorded service account is not "+
			"an operator to keep", got, "op")
	}
}

// The refusal set is this host's accounts rather than the compiled-in names, so
// an install that renamed one still refuses it. A default list is right about a
// default install and silently wrong here, and wrong means recording a service
// account as the operator.
func TestARenamedServiceAccountIsStillNotTheOperator(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	// What a host installed with `faramir init --exec-user` carries. The set is a
	// parameter for exactly this: no test can rename an account on the machine it
	// runs on.
	renamed := map[string]bool{"root": true, "faramir-runner": true}
	t.Setenv("SUDO_USER", "faramir-runner")
	if got := operatorName(renamed, ""); got == "faramir-runner" {
		t.Error("a renamed executor account was taken for the operator")
	}
	// And the compiled-in name is not refused on such a host, there being no
	// account of that name to refuse: the set says what this install has.
	t.Setenv("SUDO_USER", hostlayout.DefaultExecUser)
	if got := operatorName(renamed, ""); got != hostlayout.DefaultExecUser {
		t.Errorf("operatorName = %q, want %q: the default name is not this host's "+
			"executor, so it is an ordinary account here", got, hostlayout.DefaultExecUser)
	}
}

// What notTheOperator reads. Held because the whole point of the change is that
// this comes off the units rather than out of the binary, and a set missing an
// account is one that records it as the operator.
func TestTheRefusalSetCarriesRootAndEveryServiceAccount(t *testing.T) {
	refused := notTheOperator()
	if !refused["root"] {
		t.Error("root is not refused")
	}
	for _, account := range hostunit.InstalledAccounts() {
		if !refused[account] {
			t.Errorf("%q is installed as a service account and is not refused", account)
		}
	}
	if len(refused) != len(hostunit.InstalledAccounts())+1 {
		t.Errorf("the set holds %d entries, want root plus the %d service accounts",
			len(refused), len(hostunit.InstalledAccounts()))
	}
}

// `init` writes the units, so on a first install there are none to read and
// InstalledAccounts can only offer the compiled-in names. The accounts that run
// is naming have to join them, or a host installed with --exec-user would not
// refuse the account it is about to create.
func TestInitRefusesTheAccountsItIsNaming(t *testing.T) {
	t.Setenv(protocol.OperatorEnv, "")
	t.Setenv("SUDO_USER", "")
	refused := notTheOperator("faramir-runner", "", "")
	if !refused["faramir-runner"] {
		t.Error("an account this run names is not refused")
	}
	if !refused["root"] {
		t.Error("root is not refused")
	}
	// An empty name is a flag nobody passed, not an account called "".
	if refused[""] {
		t.Error("the empty string is refused, so a flag left out names an account")
	}
	// And the installed names are still there beside them.
	for _, account := range hostunit.InstalledAccounts() {
		if !refused[account] {
			t.Errorf("%q is installed and is not refused", account)
		}
	}
}
