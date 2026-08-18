// Package cli names the subcommands once, for the dispatcher in cmd/faramir and
// the guard's sanction rule.  Operator subcommands have their arguments left
// unscanned, `faramir run --env A=faramir://a` being the sanctioned way to name a
// secret; internal ones are the roles systemd and the agent run, and are denied
// like any other privileged command.
package cli

// Operator is every subcommand a person runs, and what the guard sanctions.
// One missing from both lists has its arguments scanned, which is a false
// denial rather than a hole.  Under sudo the guard sanctions all of these but
// `escalations`, `approve` and `deny`, which it denies: those three read and
// decide an escalation, and the account the agent runs as must not answer the
// question it raised.  Reading what is waiting is as much the operator's as
// answering it.
//
// A grouped command is named in full, every token, rather than by its parent.
// Naming the parent alone would sanction every subcommand added under it later,
// which is a widening nobody decides and nobody sees in a diff; spelled out,
// adding one is a line here.
var Operator = []string{
	"run",
	"redact",
	"status",
	// version, help and completion are cobra's as much as faramir's: the last
	// two it generates, and all three answer without reaching the broker.
	"version",
	"help",
	"completion",
	"init",
	"init-project",
	"secret add",
	"secret edit",
	"secret ls",
	"secret rm",
	"secret refs",
	"recipient add",
	"recipient rm",
	"recipient ls",
	"recipient reseal",
	"link add",
	"link rm",
	"link ls",
	"logs",
	"escalations",
	"approve",
	"deny",
	"doctor",
	"reload",
	"uninstall",
}

// Internal is the roles run by systemd (broker, keeper, exec), by the agent's
// harness (mcp, guard) and by PAM inside a brokered command (pam-approve),
// each spelled as its unit, account or PAM service is.
var Internal = []string{
	"broker",
	"keeper",
	"exec",
	"mcp",
	"guard",
	"pam-approve",
	// What doctor runs under runuser to answer access(2) as another account.
	"access",
	// What `link add` runs under runuser to ask whether the broker's own account
	// can read a linked file, before the entry is written.
	"read-link",
}
