// Package cli names the subcommands once, for the dispatcher in cmd/faramir and
// the guard's sanction rule.  Operator subcommands have their arguments left
// unscanned, `faramir run --env A=secret://a` being the sanctioned way to name a
// secret; internal ones are the roles systemd and the agent run, and are denied
// like any other privileged command.
package cli

// Operator is every subcommand a person runs, and the exact set the guard
// sanctions.  One missing from both lists has its arguments scanned, which is a
// false denial rather than a hole.
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
	"rekey",
	"logs",
	"doctor",
	"reload",
	"uninstall",
}

// Internal is the roles run by systemd (broker, keeper, exec) and by the agent's
// harness (mcp, guard), each spelled as its unit and account are.
var Internal = []string{
	"broker",
	"keeper",
	"exec",
	"mcp",
	"guard",
}
