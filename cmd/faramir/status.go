package main

import "github.com/spf13/cobra"

// opStatus is the wire name and the command name both.
const opStatus = "status"

// newStatusCmd asks the broker the one no-argument question it serves.
func newStatusCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     opStatus,
		Short:   "Show what the broker loaded and what it can reach",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// Only run has --quiet.
			return codeErr(send(opStatus, socketDefault(), map[string]any{"op": opStatus}, o.json, true))
		},
	}
	o.add(c)
	return c
}
