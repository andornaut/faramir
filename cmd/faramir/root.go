package main

import (
	"errors"
	"fmt"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/version"
)

// The three kinds of subcommand, in the order the help lists them.  A command
// without a group would be listed under "Additional Commands", which is how a
// new one announces that it was added without deciding who runs it.
const (
	groupOperator     = "operator"
	groupProvisioning = "provisioning"
	groupInternal     = "internal"
)

// usageError marks a wrong invocation: an unknown command, an unknown flag, or
// an argument a command does not take.  faramir exits 2 for these and 1 for a
// command that ran and failed, so that a script can tell them apart.
type usageError struct{ err error }

func (e usageError) Error() string { return e.err.Error() }

func (e usageError) Unwrap() error { return e.err }

// usagef reports a wrong invocation, as an argument validator does.
func usagef(format string, a ...any) error { return usageError{fmt.Errorf(format, a...)} }

// exitCodeError carries a status a command has already explained on its own
// stderr: a brokered command's own exit status, or the 127 that says a program
// could not be started.  Its message is never printed.
type exitCodeError struct{ code int }

func (e *exitCodeError) Error() string { return fmt.Sprintf("exit status %d", e.code) }

// codeErr turns a subcommand's status into the error a RunE returns.  nil for
// success, so the common path stays an ordinary return.
func codeErr(code int) error {
	if code == 0 {
		return nil
	}
	return &exitCodeError{code}
}

// exitCode returns the status faramir should exit with for the given error.
func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var e *exitCodeError
	if errors.As(err, &e) {
		return e.code
	}
	var u usageError
	if errors.As(err, &u) {
		return 2
	}
	return 1
}

// runCommand executes one subcommand against args on its own, which is how the
// tests reach a command without going through the root.
func runCommand(c *cobra.Command, args []string) int {
	c.SetArgs(args)
	return exitCode(c.Execute())
}

// newRootCmd assembles every subcommand.  The groups are what the help is
// organised by, and cli.Operator and cli.Internal name the same set for the
// guard; TestEverySubcommandIsNamedForTheGuard holds the two together.
func newRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "faramir <command> [options] [-- program [args...]]",
		Short: "A secrets broker for local AI coding agents",
		Long: "A secrets broker for local AI coding agents: it runs the commands that need\n" +
			"credentials and keeps the values out of the agent's context.\n\n" +
			"Every command that talks to the broker accepts --socket PATH (default\n" +
			"$FARAMIR_SOCKET, else " + defaultSocket + ") and --json.\n\n" +
			"Name secrets with --env NAME=secret://ref, or --env-file for a file of them.\n\n" +
			"Secrets are injected as environment variables only; they are never substituted\n" +
			"into the command line.",
		Version:       version.Version,
		SilenceErrors: false,
		// Naming a command is how anything happens, and --help is how help is
		// asked for, so a bare `faramir` is a wrong invocation rather than a
		// request for the help it used to print.
		Args: func(c *cobra.Command, args []string) error {
			if len(args) > 0 {
				return usagef("unknown command %q for %q", args[0], c.CommandPath())
			}
			return usagef("%s requires a command", c.CommandPath())
		},
		// Never reached, since the arguments never validate, but a command cobra
		// does not consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
		// Runs once the arguments have been accepted and before any command does
		// its work, which is where a failure stops being a wrong invocation worth
		// printing usage for.
		PersistentPreRunE: func(c *cobra.Command, args []string) error {
			c.SilenceUsage = true
			return nil
		},
	}

	root.AddGroup(
		&cobra.Group{ID: groupOperator, Title: "Commands:"},
		&cobra.Group{ID: groupProvisioning, Title: "Provisioning (require root; they act on files, and ask a running broker where the install is):"},
		&cobra.Group{ID: groupInternal, Title: "Run by systemd and by the coding agent, not by you:"},
	)

	// `faramir version` as well as --version, because it was a subcommand
	// before cobra and is written down as one.
	root.SetVersionTemplate("faramir {{.Version}}\n")
	root.AddCommand(&cobra.Command{
		Use:     "version",
		Short:   "print the version and exit",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			fmt.Println("faramir " + version.Version)
			return nil
		},
	})

	root.AddCommand(
		newRunCmd(),
		newRedactCmd(),
		newCallCmd("list_secrets", "list secret refs (names only)"),
		newCallCmd("status", "show broker status"),
		newKeygenCmd(),
	)
	root.AddCommand(
		newInitCmd(),
		newInitProjectCmd(),
		newEditCmd(),
		newRekeyCmd(),
		newLogsCmd(),
		newApprovalsCmd(),
		newApproveCmd(),
		newDenyCmd(),
		newDoctorCmd(),
		newReloadCmd(),
		newUninstallCmd(),
	)
	root.AddCommand(
		newBrokerCmd(),
		newKeeperCmd(),
		newExecCmd(),
		newPamApproveRootCmd(),
		newMCPCmd(),
		newGuardCmd(),
	)

	// A flag cobra could not parse is a wrong invocation, and exits 2 like one.
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error { return usageError{err} })
	// The generated completion command is not one of the three groups, and
	// still works when it is not listed.
	root.CompletionOptions.HiddenDefaultCmd = true
	// Out is deliberately left unset.  cobra writes a usage block through
	// OutOrStderr, so pointing Out at stdout would send the usage that follows
	// a wrong invocation there, where a caller reading the command's output
	// would receive it.  Unset, help still reaches stdout, which cobra writes
	// through OutOrStdout.
	return root
}

// noArgs refuses operands.  cobra.NoArgs reports them as an unknown command,
// which misdescribes a command that takes no operands at all rather than one
// that was misspelled.
func noArgs(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usagef("%s takes no arguments, but got %q", c.CommandPath(), args[0])
	}
	return nil
}

// atMostOneArg refuses a second operand, naming what the first one is for.
func atMostOneArg(what string) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) > 1 {
			return usagef("%s takes at most one %s", c.CommandPath(), what)
		}
		return nil
	}
}

// exactlyOneArg requires one operand, naming what it is for.  Cobra's own
// message ("accepts 1 arg(s), received 0") names neither the command nor what
// it wanted.
func exactlyOneArg(what string) cobra.PositionalArgs {
	return func(c *cobra.Command, args []string) error {
		if len(args) != 1 {
			return usagef("%s requires one %s", c.CommandPath(), what)
		}
		return nil
	}
}

// firstArg returns the first operand, or "" when there is none.  A command
// whose operand is optional reads it through this rather than indexing.
func firstArg(args []string) string {
	if len(args) == 0 {
		return ""
	}
	return args[0]
}
