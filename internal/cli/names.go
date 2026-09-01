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
	"block add",
	"block ls",
	"block rm",
	// completion, help and version answer without reaching the broker.
	"completion",
	"doctor",
	"enrol",
	"help",
	"init",
	"link add",
	"link ls",
	"link rm",
	"logs",
	"reader add",
	"reader ls",
	"reader reseal",
	"reader rm",
	"redact",
	"refs",
	"reload",
	"run",
	"status",
	"sudo approve",
	"sudo ls",
	"sudo reject",
	"sudo watch",
	"uninstall",
	"vault add",
	"vault edit",
	"vault ls",
	"vault rm",
	"version",
}

// Agent is the subcommands the coding agent may run, and so the only ones whose
// own arguments the guard leaves unscanned: a ref in `run --env` would
// otherwise trip the patterns that exist to catch a value being read. The
// child a `redact --` runs is scanned all the same; only `run`'s child is
// exempt, the broker guarding that one.
//
// Everything in Operator and absent here acts on the install rather than
// through it, and is refused to the agent's shell.
var Agent = []string{
	"completion",
	"help",
	"redact",
	"refs",
	"run",
	"status",
	"version",
}

// ReadOnly is the operator subcommands that describe the install without
// changing it, without printing a value, and without needing root. They are not
// refused to the agent.
//
// Refusing them protected nothing: each already answered as `faramir run --
// faramir <command>`, which takes no root and raises no approval, so the direct
// spelling was refused while the brokered one worked. A rule two spellings
// disagree on is one an agent works around rather than reads.
//
// Root is the test, not read-versus-write. `logs` reads and changes nothing and
// is still absent, because it needs root and needs it through the broker as
// well: allowing it would answer with a permission error naming `sudo faramir
// logs`, which stays refused. A refusal that says to ask the operator is the
// truthful answer there, and is what adviceOperator exists to give.
//
// Not folded into Agent, which answers a different question: Agent is whose
// arguments the guard leaves unscanned, and these are scanned like anything
// else.
//
// The write verbs stay refused, and so does every `sudo` verb: the account the
// agent runs as must not answer the escalation it raised.
var ReadOnly = []string{
	"block ls",
	"doctor",
	"link ls",
	"reader ls",
}

// OperatorOnly is Operator without Agent or ReadOnly, in Operator's order: the
// subcommands the deny rules refuse to the agent. Derived rather than written
// twice, so a command added to Operator is refused until somebody decides
// otherwise.
func OperatorOnly() []string {
	out := make([]string, 0, len(Operator))
	for _, name := range Operator {
		if !slices.Contains(Agent, name) && !slices.Contains(ReadOnly, name) {
			out = append(out, name)
		}
	}
	return out
}

// Internal is the roles run by systemd (broker, keeper, exec), by the agent's
// harness (guard) and by PAM inside a brokered command (pam-escalate), each
// spelled as its unit, account or PAM service is.
var Internal = []string{
	"broker",
	"keeper",
	"exec",
	"guard",
	"pam-escalate",
	// What doctor runs under runuser to answer access(2) as another account.
	"access",
	// What `link add` runs under runuser to ask whether the broker's own account
	// can read a linked file, before the entry is written.
	"read-link",
}
