package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/enrol"
)

func newUnenrolCmd() *cobra.Command {
	var dryRun, asJSON, missing bool
	c := &cobra.Command{
		Use:   "unenrol [flags] [DIR]",
		Short: "Remove project enrolment or forget missing project records",
		Long: "Remove project routing hooks, the marked project credentials section and\n" +
			"the enrolment record for every agent in one tree. DIR defaults to the\n" +
			"current working directory. Retain permission rules, global configuration\n" +
			"and filesystem sharing. Start fresh agent sessions afterwards.\n\n" +
			"If DIR is missing, remove only its matching enrolment record.\n" +
			"--missing forgets all confirmed missing records and accepts no DIR.\n" +
			"Missing paths can include unmounted storage; cleanup is explicit.",
		GroupID: groupOperator,
		Args: func(c *cobra.Command, args []string) error {
			if missing && len(args) > 0 {
				return usagef("--missing cannot be combined with a directory")
			}
			return atMostOneArg("directory")(c, args)
		},
		RunE: func(c *cobra.Command, args []string) error {
			dir, err := resolveConfigDir(socketDefault())
			if err != nil {
				reportErr("unenrol", err)
				return codeErr(1)
			}
			opts := enrol.UnenrolOptions{
				Dir: firstArg(args), AgentUser: operatorFromConfig(config.FileIn(dir)),
				ConfigDir: dir, DryRun: dryRun, Missing: missing,
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
				fmt.Fprintln(os.Stderr, unenrolSummary(report))
			}
			return nil
		},
	}
	c.Flags().BoolVar(&dryRun, "dry-run", false, "report what would change and write nothing")
	c.Flags().BoolVar(&asJSON, "json", false, "print the report as JSON")
	c.Flags().BoolVar(&missing, "missing", false, "forget all confirmed missing project records (no DIR); includes unmounted paths")
	return c
}

func unenrolSummary(report enrol.UnenrolReport) string {
	if report.RecordOnly {
		count := len(report.MissingRecords)
		if count == 0 {
			if report.Bulk {
				return "no missing enrolment records"
			}
			return "no enrolment record for missing project " + report.Dir
		}
		if report.DryRun {
			return fmt.Sprintf("dry run: would forget %d missing enrolment record(s)", count)
		}
		return fmt.Sprintf("forgot %d missing enrolment record(s)", count)
	}
	if report.DryRun {
		return "dry run: would unenrol " + report.Dir
	}
	return "unenrolled " + report.Dir
}
