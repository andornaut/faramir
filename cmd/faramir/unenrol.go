package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/enrol"
)

func newUnenrolCmd() *cobra.Command {
	var dryRun, asJSON bool
	c := &cobra.Command{
		Use:   "unenrol [options] [DIR]",
		Short: "Remove one working tree's routing and enrolment record",
		Long: "Remove project routing hooks, the marked project credentials section and\n" +
			"the enrolment record for every agent in one tree. DIR defaults to the\n" +
			"current working directory. Retain permission rules, global configuration\n" +
			"and filesystem sharing. Start fresh agent sessions afterwards.",
		GroupID: groupOperator,
		Args:    atMostOneArg("directory"),
		RunE: func(c *cobra.Command, args []string) error {
			dir, err := resolveConfigDir(socketDefault())
			if err != nil {
				reportErr("unenrol", err)
				return codeErr(1)
			}
			opts := enrol.UnenrolOptions{
				Dir: firstArg(args), AgentUser: operatorFromConfig(config.FileIn(dir)),
				ConfigDir: dir, DryRun: dryRun,
			}
			if !asJSON {
				opts.Log = func(line string) { fmt.Fprintln(os.Stderr, line) }
			}
			report, err := enrol.Unenrol(opts)
			if err != nil {
				reportErr("unenrol", err)
			}
			if asJSON {
				if code := printJSON("unenrol", report); code != 0 {
					return codeErr(code)
				}
			}
			if err != nil {
				return codeErr(1)
			}
			if !asJSON {
				for _, warning := range report.Warnings {
					fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
				}
				if dryRun {
					fmt.Fprintf(os.Stderr, "dry run: would unenrol %s\n", report.Dir)
				} else {
					fmt.Fprintf(os.Stderr, "unenrolled %s\n", report.Dir)
				}
			}
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change and write nothing")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	return c
}
