package main

import (
	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/guard"
	"github.com/andornaut/faramir/internal/mcp"
)

// The MCP server and the PreToolUse hook parse their own arguments, in their
// own packages, because each speaks a protocol whose shape is not faramir's:
// flags reach them untouched rather than through a flag set defined here.
func newMCPCmd() *cobra.Command {
	c := &cobra.Command{
		Use:                "mcp",
		Short:              "Run the MCP stdio server",
		GroupID:            groupInternal,
		DisableFlagParsing: true,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(mcp.Run(args))
		},
	}
	return c
}

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
