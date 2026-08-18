package main

import "github.com/spf13/cobra"

// newSopsCmd groups what is done to the managed store: edit a file, change who
// can read it, and re-encrypt what is there.  A parent rather than that many
// top-level verbs, because the help said nothing about them being one subject
// while they sat between `logs` and `doctor`.
//
// Minting a key is not here.  Three of the four ways a recipient arises mint
// nothing -- another operator's key, a second host's own, a plugin's -- and the
// fourth is a backup identity, which has to be minted on the machine that will
// hold it rather than on the host it is the backup for.  A command here would
// have minted it in the wrong place.
func newSopsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "sops",
		Short:   "manage the sops store: edit a file, change who can read it, re-encrypt it",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		// Never reached, the arguments never validating; a command cobra does not
		// consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newEditCmd(), newRekeyCmd(), newRecipientCmd())
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
