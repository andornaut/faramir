// Package cli names the subcommands, once, for the two places that must agree
// about them: the dispatcher in cmd/faramir, and the guard's sanction rule.
//
// The split is not cosmetic.  Operator subcommands are sanctioned by the guard,
// meaning their arguments are not scanned for secrets, because `faramir run
// --env A=secret://a` is the sanctioned way to name one.  Internal subcommands
// are the roles systemd and the coding agent run, and must be denied like any
// other privileged command: `sudo faramir broker` is not something an agent has
// a reason to run.
package cli

// Operator is every subcommand a person runs, and the exact set the guard
// sanctions.  A subcommand added to the dispatcher and not to one of these two
// lists gets its arguments scanned, which is a false denial someone reports,
// rather than a hole nobody sees.
var Operator = []string{
	"run",
	"redact",
	"list-secrets",
	"status",
	"keygen",
	"version",
	"help",
	"init",
	"init-project",
	"edit",
	"doctor",
	"reload",
	"uninstall",
}

// Internal is the roles run by systemd (broker, keeper, exec) and by the coding
// agent's own harness (mcp, guard).  Each is spelled as its unit and its account
// are spelled.
var Internal = []string{
	"broker",
	"keeper",
	"exec",
	"mcp",
	"guard",
}
