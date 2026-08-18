package main

import "github.com/spf13/cobra"

// newSecretsCmd groups what is done to the files: write one, edit one, list
// them, remove one, and ask the broker which refs they name.
//
// Named for the subject rather than for sops, which is the format underneath
// and the tool that reads it.  What an operator acts on here is their secrets;
// that they are sops files governed by a creation rule is how, not what.  Who
// may read them is `faramir recipient`, a noun of its own beside this one and
// beside `faramir link`.
//
// Minting a key is not here.  Three of the four ways a recipient arises mint
// nothing -- another operator's key, a second host's own, a plugin's -- and the
// fourth is a backup identity, which has to be minted on the machine that will
// hold it rather than on the host it is the backup for.  A command here would
// have minted it in the wrong place.
func newSecretsCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "secrets",
		Short:   "the managed store: write, edit, list and remove secrets",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		// Never reached, the arguments never validating; a command cobra does not
		// consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newAddCmd(), newEditCmd(), newSecretsListCmd(),
		newSecretsRemoveCmd(), newSecretsRefsCmd())
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
