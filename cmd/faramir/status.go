package main

import (
	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/brokerclient"
)

// newStatusCmd asks the broker the one no-argument question it serves.
func newStatusCmd() *cobra.Command {
	var o brokerOptions
	c := &cobra.Command{
		Use:     brokerclient.OpStatus,
		Short:   "Show what the broker loaded and what it can reach",
		GroupID: groupOperator,
		Args:    noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			// Only run has --quiet.
			return codeErr(send(brokerclient.OpStatus, socketDefault(), map[string]any{"op": brokerclient.OpStatus}, o.json, true))
		},
	}
	o.add(c)
	return c
}
