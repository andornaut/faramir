package main

import (
	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/termui"
)

// addColorFlag registers --color on a command that prints a report to a human.
// Declared once rather than once per command: several commands paint, and the
// flag an operator types at one of them has to be the flag the others take.
// Not persistent on the root command, which would advertise it on `run`,
// `exec` and the daemons, where it decides nothing.
//
// Checked as it is parsed, so a bad value is a usage error that exits 2 before
// the command runs, whatever the command checks first.
func addColorFlag(c *cobra.Command, when *string) {
	*when = "auto"
	c.Flags().Var((*colorFlag)(when), "color", "colourise: auto, always or never")
}

// colorFlag is --color's value, refused at parse time unless termui accepts it.
type colorFlag string

func (f *colorFlag) String() string { return string(*f) }

func (f *colorFlag) Type() string { return "string" }

func (f *colorFlag) Set(value string) error {
	if _, err := termui.NewPalette(value); err != nil {
		return err
	}
	*f = colorFlag(value)
	return nil
}
