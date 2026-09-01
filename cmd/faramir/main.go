// Command faramir runs a credential-bearing command through the secrets broker.
//
// Secrets are injected as environment variables only; they are never
// substituted into the command line.
package main

import (
	"fmt"
	"os"
	"os/user"

	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/protocol"
)

const defaultSocket = "/run/faramir/broker.sock"

// socketDefault is where every subcommand looks for the broker, and
// FARAMIR_SOCKET is the only way to move it: no subcommand takes a socket
// flag, an install writing `[server] socket_path` from a fixed run directory
// and one variable moving the lot rather than a flag per command.
func socketDefault() string {
	if v := os.Getenv("FARAMIR_SOCKET"); v != "" {
		return v
	}
	return defaultSocket
}

func main() { os.Exit(run(os.Args[1:])) }

func run(args []string) int {
	root := newRootCmd()
	root.SetArgs(args)
	return exitCode(root.Execute())
}

// requireRoot refuses a command that must run as root, naming how to re-run it.
// The escalation commands use requireRootToAnswer instead: they must not
// suggest sudo, a warm sudo timestamp being what their check exists to keep out
// of the agent's reach.
func requireRoot(command string) bool {
	if os.Geteuid() == 0 {
		return true
	}
	fmt.Fprintf(os.Stderr, "faramir %s must run as root: try 'sudo faramir %s'\n",
		command, command)
	return false
}

// operatorName resolves the account that works in the tree: --agent-user, then
// $FARAMIR_OPERATOR, then SUDO_USER so `sudo faramir init` needs no flag, then
// the caller. root is not an answer at any position: chowning a checkout to root
// would take it from its owner, so reaching root another way means passing
// --agent-user.
//
// $FARAMIR_OPERATOR outranks SUDO_USER because it is set only inside a brokered
// command, and there sudo's caller is the executor rather than a person: the
// broker writes it from the live config and the grant's env_file carries it
// through to root, which is what etc/sudo-env.tmpl exists to do. Ahead of
// SUDO_USER rather than behind it, unlike the config fallback in
// operatorFromConfig: a stale config should not outrank a person answering in
// the present tense, but a brokered run has no person in SUDO_USER to outrank.
//
// refused is the accounts that cannot be the answer whichever position they
// arrive in; notTheOperator builds this host's.
func operatorName(refused map[string]bool, flagValue string) string {
	candidates := []string{flagValue, os.Getenv(protocol.OperatorEnv), os.Getenv("SUDO_USER")}
	if current, err := user.Current(); err == nil {
		candidates = append(candidates, current.Username)
	}
	for _, candidate := range candidates {
		if candidate != "" && !refused[candidate] {
			return candidate
		}
	}
	return ""
}

// notTheOperator is the accounts that cannot be the operator on this host. root
// chowns a checkout away from its owner; faramir's own service accounts hold
// none of the operator's configuration, and one of them reaching the resolver
// means SUDO_USER was read from a brokered command whose $FARAMIR_OPERATOR was
// missing.
//
// The names this host actually uses, read off the installed units, rather than
// the compiled-in defaults. A default list is right about a default install and
// silently wrong about a renamed one, and there being wrong means recording a
// service account as the operator: the rules are then rendered against its home
// and every blocked path under the operator's own loses the spellings a shell
// expands to it.
//
// A parameter rather than read inside the resolver, so what a run refuses is
// visible at the call site and a test can name accounts this host does not have.
func notTheOperator(alsoRefused ...string) map[string]bool {
	accounts := hostunit.InstalledAccounts()
	refused := make(map[string]bool, len(accounts)+len(alsoRefused)+1)
	// Whatever the units say, and root at every install.
	refused["root"] = true
	for _, account := range append(accounts, alsoRefused...) {
		if account != "" {
			refused[account] = true
		}
	}
	return refused
}

// useLs is the Use line every ls subcommand shares. Spelled once: several
// commands take it, and the one an operator types at any of them has to read
// the same as the rest.
const useLs = "ls [options]"
