package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/enrol"
)

func newShareCmd() *cobra.Command {
	var group string
	var dryRun, asJSON bool
	c := &cobra.Command{
		Use:   "share --group NAME [flags] DIR",
		Short: "Grant group access without enrolling a tree",
		Long: "Grant group read/write access and directory traversal without enrolling a tree.\n" +
			"DIR and --group are required. The root gains group rwx and setgid.\n" +
			"Only group-readable, non-hidden descendants are shared. Hidden entries,\n" +
			"private files and directories, declared credential paths and symlinks are\n" +
			"left alone. Name a required hidden subtree directly. User ownership is\n" +
			"preserved. No agent\n" +
			"configuration or enrollment record is written. Ancestors are only checked.",
		GroupID: groupOperator,
		Args:    exactlyOneArg("directory"),
		RunE: func(c *cobra.Command, args []string) error {
			if group == "" {
				return usagef("name --group NAME")
			}
			dir, err := resolveConfigDir(socketDefault())
			if err != nil {
				reportErr("share", err)
				return codeErr(1)
			}
			opts := enrol.Options{
				Dir: args[0], AgentUser: operatorFromConfig(config.FileIn(dir)),
				ConfigDir: dir, ClientGroup: group, DryRun: dryRun,
			}
			if !asJSON {
				opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
			}
			report, err := enrol.ShareOnly(opts)
			if err != nil {
				reportErr("share", err)
			}
			if asJSON {
				if code := printJSON("share", report); code != 0 {
					return codeErr(code)
				}
			}
			if err != nil {
				return codeErr(1)
			}
			if !asJSON {
				verb := "shared"
				if dryRun {
					verb = "dry run: would share"
				}
				fmt.Fprintf(os.Stderr, "%s %s (group %s), without enrollment\n", verb, report.Dir, report.ClientGroup)
			}
			return nil
		},
	}
	c.Flags().StringVar(&group, "group", "", "group to grant access to (required)")
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change and write nothing")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return c
}
