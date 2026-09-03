package main

// faramir pam-escalate: the authentication step of faramir's own PAM service.
//
// sudo execs this, as root, and reads nothing from it but the exit status: zero
// authenticates the call, anything else refuses it, so every path here fails
// closed. No password is involved: it asks the broker whether the brokered
// command making this call was approved by a human, which is why an escalation
// cannot be carried to a later command.
//
// It says which command is asking by walking /proc up from sudo and sending the
// pids it finds. PAM does not pass the caller's environment to a module, and it
// does not have to: this runs as root and the ancestry is the kernel's. Nothing
// here is trusted on its own -- the broker asks the executor which of its runs
// forked one of those processes, and the executor checks each against a handle it
// took at the fork, so a pid the kernel has since handed on answers for nothing.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/andornaut/faramir/internal/brokerclient"
	"github.com/andornaut/faramir/internal/escalation"
)

// runPamEscalateCommand applies the rule that nothing but a real escalation
// exits 0. PAM reads the status as an auth pass, and --help and a usage error
// both leave cobra with 0, so the status is taken from whether an escalation
// happened rather than from how the command returned.
//
// Every caller goes through here: the root registers a command that forwards
// its arguments untouched, so there is one path and one place the rule lives.
func runPamEscalateCommand(args []string) int {
	granted := false
	code := runCommand(newPamEscalateCmd(&granted), args)
	if code == 0 && !granted {
		return 2
	}
	return code
}

type pamEscalateFlags struct {
	account string
}

// newPamEscalateCmd decides one sudo, setting granted only on the path an
// escalation was actually given on. Run it through runPamEscalateCommand, which
// is what reads that.
func newPamEscalateCmd(granted *bool) *cobra.Command {
	var f pamEscalateFlags
	c := &cobra.Command{
		Use:   "pam-escalate",
		Short: "Ask whether one sudo may proceed, inside a brokered command (run by PAM)",
		Args:  noArgs,
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runPamEscalate(f, granted))
		},
	}
	c.Flags().StringVar(&f.account, "account", "", "the account this PAM service is for")
	return c
}

// pamSocket is the broker this helper asks, and it is the compiled-in path
// rather than socketDefault(): every other subcommand lets $FARAMIR_SOCKET move
// it, and this one runs inside the sudo of the account being decided about,
// whose environment pam_exec hands the module unchanged. A broker named there
// is a broker that caller could have started, and it would answer "approved" to
// every question it was asked. There is no flag either, for the same reason one
// path and one socket is the whole of it.
func pamSocket() string { return defaultSocket }

// ancestryOf is escalation.Ancestry, and a variable so a test can say what is
// above this process. A test binary's own ancestors are whatever ran `go test`,
// so the one branch that cannot otherwise be reached is the one where nothing
// above is readable -- which is the branch that must refuse without the broker
// being contacted at all.
var ancestryOf = escalation.Ancestry

func runPamEscalate(f pamEscalateFlags, granted *bool) int {
	// PAM_TYPE and PAM_USER come from pam_exec. Checked, so a service file
	// pointed at another account, or at the account stage rather than auth,
	// cannot authenticate anything.
	if kind := os.Getenv("PAM_TYPE"); kind != "auth" {
		fmt.Fprintf(os.Stderr, "faramir pam-escalate: PAM_TYPE is %q; this service "+
			"handles authentication only\n", kind)
		return 1
	}
	if f.account != "" && os.Getenv("PAM_USER") != f.account {
		fmt.Fprintf(os.Stderr, "faramir pam-escalate: PAM_USER is %q, not %q: this "+
			"service authenticates one account\n", os.Getenv("PAM_USER"), f.account)
		return 1
	}

	// The kernel's account of who forked this, up to the executor. Sent whole: the
	// helper cannot tell which of them the executor started, and asking it to
	// guess would be asking the caller's own process tree to decide.
	ancestors := ancestryOf(os.Getppid())
	if len(ancestors) == 0 {
		// Nothing above this call, which is what a `sudo` typed by hand as the
		// executor's account looks like once its shell is gone.
		fmt.Fprintln(os.Stderr, "faramir pam-escalate: no process above this sudo "+
			"could be read, so the request cannot be attributed to a brokered command")
		return 1
	}
	approved, reason, err := brokerclient.Escalate(pamSocket(), ancestors)
	if err != nil {
		fmt.Fprintf(os.Stderr, "faramir pam-escalate: %v\n", err)
		return 1
	}
	if !approved {
		fmt.Fprintf(os.Stderr, "faramir pam-escalate: %s\n", reason)
		return 1
	}
	*granted = true
	return 0
}
