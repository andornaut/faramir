package main

import "github.com/spf13/cobra"

// newVaultCmd groups what is done to the files: write one, edit one, list them,
// remove one, and ask the broker which refs they name.
//
// A vault, not a secret: each of these files holds several, so `add` writes a
// container rather than a credential and the singular would name the wrong
// thing.  It is also the word ansible-vault uses for the same object, and the
// one the deny rules already use for a protected credential store, so an agent
// reading "vault files are off limits" and an operator running `faramir vault
// edit` mean the same thing by it.
//
// Not sops, which is the format underneath and the tool that reads it: what an
// operator acts on is the vault, and that it is governed by a creation rule is
// how rather than what.  Who may read them is `faramir recipient`, a noun of its
// own beside this one and beside `faramir link`.
//
// Minting a key is not here.  Three of the four ways a recipient arises mint
// nothing -- another operator's key, a second host's own, a plugin's -- and the
// fourth is a backup identity, which has to be minted on the machine that will
// hold it rather than on the host it is the backup for.  A command here would
// have minted it in the wrong place.
func newVaultCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "vault",
		Short:   "the managed vaults: write, edit, list and remove them",
		GroupID: groupProvisioning,
		Args:    requiresSubcommand,
		// Never reached, the arguments never validating; a command cobra does not
		// consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newAddCmd(), newEditCmd(), newVaultListCmd(), newVaultRemoveCmd())
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
