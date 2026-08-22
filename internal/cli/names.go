// Package cli names the subcommands once, for the dispatcher in cmd/faramir and
// the guard's sanction rule. Internal subcommands are the roles systemd and
// the agent run, and are denied like any other privileged command.
package cli

import "slices"

// Operator is every subcommand a person runs. One missing from both lists has
// its arguments scanned, which is a false denial rather than a hole.
// The `sudo` group is denied to the agent's shell, every verb of it: the
// account it runs as must not read or answer the question it raised.
//
// A grouped command is named in full, every token, rather than by its parent:
// naming the parent alone would sanction every subcommand added under it
// later.
var Operator = []string{
	"run",
	"redact",
	"status",
	"refs",
	// version, help and completion answer without reaching the broker.
	"version",
	"help",
	"completion",
	"init",
	"init-project",
	"vault add",
	"vault edit",
	"vault ls",
	"vault rm",
	"reader add",
	"reader rm",
	"reader ls",
	"reader reseal",
	"link add",
	"link rm",
	"link ls",
	"block add",
	"block rm",
	"block ls",
	"logs",
	"sudo ls",
	"sudo watch",
	"sudo approve",
	"sudo reject",
	"doctor",
	"reload",
	"uninstall",
}

// Agent is the subcommands the coding agent may run, and so the only ones whose
// arguments the guard leaves unscanned: a ref in `run --env`, and the text
// `redact` is scrubbing, would otherwise trip the patterns that exist to catch
// a value being read.
//
// Everything in Operator and absent here acts on the install rather than
// through it, and is refused to the agent's shell.
var Agent = []string{
	"run",
	"redact",
	"status",
	"refs",
	"version",
	"help",
	"completion",
}

// OperatorOnly is Operator without Agent, in Operator's order: the subcommands
// the deny rules refuse to the agent. Derived rather than written twice, so a
// command added to Operator is refused until somebody decides otherwise.
func OperatorOnly() []string {
	out := make([]string, 0, len(Operator))
	for _, name := range Operator {
		if !slices.Contains(Agent, name) {
			out = append(out, name)
		}
	}
	return out
}

// Internal is the roles run by systemd (broker, keeper, exec), by the agent's
// harness (mcp, guard) and by PAM inside a brokered command (pam-escalate),
// each spelled as its unit, account or PAM service is.
var Internal = []string{
	"broker",
	"keeper",
	"exec",
	"mcp",
	"guard",
	"pam-escalate",
	// What doctor runs under runuser to answer access(2) as another account.
	"access",
	// What `link add` runs under runuser to ask whether the broker's own account
	// can read a linked file, before the entry is written.
	"read-link",
}
