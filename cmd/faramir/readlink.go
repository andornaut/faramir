package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/secretlink"
)

// newReadLinkCmd answers one question: would this link produce a value? Run by
// `faramir link add` through runuser as the broker's own account, before the
// entry is written anywhere.
//
// Its own subcommand rather than a check inside `link add`, for the reason
// `faramir access` exists: the question is about a particular uid, and the only
// way to ask it is to be that uid. The parent runs as root, which can read
// anything and would answer yes to a file the broker cannot open.
//
// **It never prints the value.**  On success it prints nothing; on a selector
// that named nothing it prints the selectors the file does offer, which are
// names. That is the whole of its output contract, and what makes it safe for
// the parent to relay to a terminal.
func newReadLinkCmd() *cobra.Command {
	var path, kind, key string
	c := &cobra.Command{
		Use:    "read-link --path FILE --type TYPE [--key KEY]",
		Short:  "Report whether this account can read a linked secret",
		Hidden: true,
		Args:   noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			if path == "" || kind == "" {
				fmt.Fprintln(os.Stderr, "faramir read-link: --path and --type are required")
				return codeErr(2)
			}
			if _, err := secretlink.Read(path, kind, key); err != nil {
				// Refusal adds the selectors the file offers, and is what `link add`
				// prints for the same failure found as root, so one wrong --key reads
				// the same whichever account met it first.
				fmt.Fprintf(os.Stderr, "%v\n", secretlink.Refusal(path, kind, err))
				return codeErr(1)
			}
			return nil
		},
	}
	c.Flags().StringVar(&path, "path", "", "the file to read")
	c.Flags().StringVar(&kind, "type", "", "how to read it")
	c.Flags().StringVar(&key, "key", "", "what to select out of it")
	return c
}
