package main

import "github.com/spf13/cobra"

// addColorFlag registers --color on a command that prints a report to a human.
// Declared once rather than once per command: several commands paint, and the
// flag an operator types at one of them has to be the flag the others take.
// Not persistent on the root command, which would advertise it on `run`,
// `exec` and the daemons, where it decides nothing.
func addColorFlag(c *cobra.Command, when *string) {
	c.Flags().StringVar(when, "color", "auto", "colourise: auto, always or never")
}
