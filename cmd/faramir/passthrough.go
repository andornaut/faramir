package main

import (
	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/guard"
)

// newPamEscalateRootCmd forwards to runPamEscalateCommand rather than parsing
// here, so the rule that only an escalation exits 0 is applied in exactly one
// place whichever way pam-escalate is reached.
func newPamEscalateRootCmd() *cobra.Command {
	return &cobra.Command{
		Use:                "pam-escalate",
		Short:              "Ask whether one sudo may proceed, inside a brokered command (run by PAM)",
		GroupID:            groupInternal,
		DisableFlagParsing: true,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runPamEscalateCommand(args))
		},
	}
}

// The PreToolUse hook parses its own arguments, in its own package, because it
// speaks a protocol whose shape is not faramir's: flags reach it untouched
// rather than through a flag set defined here.
func newGuardCmd() *cobra.Command {
	c := &cobra.Command{
		Use:                "guard",
		Short:              "Run the PreToolUse hook a coding agent calls",
		GroupID:            groupInternal,
		DisableFlagParsing: true,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(guard.Run(args))
		},
	}
	return c
}
