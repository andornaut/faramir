package main

import "github.com/spf13/cobra"

// newSopsCmd groups what is done to the managed store: edit a file, change who
// can read it, re-encrypt what is there, and mint the key it is encrypted to.  A
// parent rather than that many top-level verbs, because the help said nothing
// about them being one subject while they sat between `logs` and `doctor`.
//
// `sops keygen` is the odd member and stays anyway: it needs neither root nor
// an install, minting an identity for a store that need not exist yet.  Its own
// help says so, and splitting it out would be a group of one.
func newSopsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "sops",
		Short:   "manage the sops store: edit a file, change who can read it, mint a key",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		// Never reached, the arguments never validating; a command cobra does not
		// consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newEditCmd(), newRekeyCmd(), newKeygenCmd(),
		newRecipientAddCmd(), newRecipientRemoveCmd(), newRecipientListCmd())
	return c
}

// requiresSubcommand is the argument check a grouping command takes: naming a
// subcommand is how anything happens, so a bare parent is a wrong invocation
// rather than a request for help.  The same rule the root command follows.
func requiresSubcommand(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usagef("unknown command %q for %q", args[0], c.CommandPath())
	}
	return usagef("%s requires a command", c.CommandPath())
}
