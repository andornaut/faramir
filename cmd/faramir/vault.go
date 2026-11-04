package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/steps"
	"github.com/andornaut/faramir/internal/version"
)

// newVaultCmd groups what is done to the files: write one, edit one, list them,
// remove one.
//
// A vault, not a secret: each of these files holds several. It is also the word
// ansible-vault uses for the same object and the one the deny rules use for a
// protected credential store, so an agent reading "vault files are off limits"
// and an operator running `faramir vault edit` mean the same thing by it. Not
// sops, which is the format underneath; who may read them is `faramir
// reader`.
//
// Minting a key is not here: three of the four ways a recipient arises mint
// nothing -- another operator's key, a second host's own, a plugin's -- and the
// fourth is a backup identity, which has to be minted on the machine that will
// hold it.
func newVaultCmd() *cobra.Command {
	c := &cobra.Command{
		Use:     "vault",
		Short:   "Add, edit, list and remove the encrypted secret files",
		GroupID: groupOperator,
		Args:    requiresSubcommand,
		// Never reached, the arguments never validating; a command cobra does not
		// consider runnable has its arguments ignored altogether.
		RunE: func(c *cobra.Command, args []string) error { return nil },
	}
	c.AddCommand(newAddCmd(), newEditCmd(), newVaultListCmd(), newVaultRemoveCmd())
	return c
}

// requiresSubcommand is the argument check a grouping command takes: naming a
// subcommand is how anything happens, so a bare parent is a wrong invocation.
// The same rule the root command follows.
func requiresSubcommand(c *cobra.Command, args []string) error {
	if len(args) > 0 {
		return usagef("unknown command %q for %q", args[0], c.CommandPath())
	}
	return usagef("%s requires a command", c.CommandPath())
}

// The step names a store edit reports under. "sops config" is the name `init`
// records the same file under.
const (
	stepSopsConfig  = "sops config"
	stepReseal      = "reseal"
	stepManagedFile = "managed file"
)

// storeReport is the --json document of a command that changes the managed
// store or its rule: the shared steps.Report with the version and dry_run
// fields the documents of `init` and `enrol` carry, so a configuration manager
// reads changed and steps the same way from every edit.
type storeReport struct {
	steps.Report

	Version string `json:"version"`
	DryRun  bool   `json:"dry_run,omitempty"`
}

// storeEdit is how such a command reports: a line per outcome on stderr, or
// under --json the document, printed once the command ends. Errors go to
// stderr either way.
type storeEdit struct {
	json   bool
	report storeReport
}

func newStoreEdit(dryRun, asJSON bool) *storeEdit {
	return &storeEdit{json: asJSON, report: storeReport{Version: version.Version, DryRun: dryRun}}
}

func (e *storeEdit) dryRun() bool { return e.report.DryRun }

// sayf prints an outcome line, which the document replaces under --json.
func (e *storeEdit) sayf(format string, args ...any) {
	if !e.json {
		fmt.Fprintf(os.Stderr, format, args...)
	}
}

// done prints the document under --json and returns the command's exit
// status, which a document that would not print turns into a failure. A run
// that recorded no step prints [] rather than null, for the reason `link ls`
// gives.
func (e *storeEdit) done(label string, code int) int {
	if !e.json {
		return code
	}
	if e.report.Steps == nil {
		e.report.Steps = []steps.Step{}
	}
	if printed := printJSON(label, e.report); printed != 0 {
		return printed
	}
	return code
}
