package main

// faramir access: answer access(2) for the account this process is already
// running as, and exit 0 or 1.
//
// `faramir doctor` asks whether an account can read or write a path, and the
// only honest way to ask is to be that account: access(2) answers for the
// calling process, and supplementary groups are per-process. doctor therefore
// runs this under `runuser -u ACCOUNT`.
//
// faramir's own subcommand rather than the host's `test`: some `test`
// implementations (uutils) ignore supplementary group membership, which makes
// every group-based finding wrong in both directions. It also keeps a shell
// out of it, these paths coming from --ssh-key and the config, so argv carries
// a path with no interpretation.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// newAccessCmd answers one question about one path. Internal: it is what
// doctor runs as another account.
func newAccessCmd() *cobra.Command {
	var (
		read    bool
		write   bool
		execute bool
	)
	c := &cobra.Command{
		Use:     "access [options] PATH",
		Short:   "Answer access(2) as this process's own account (run by doctor)",
		GroupID: groupInternal,
		Args: func(c *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usagef("faramir access: one path is required")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runAccess(args[0], read, write, execute))
		},
	}
	c.Flags().BoolVarP(&read, "read", "r", false, "may this account read it")
	c.Flags().BoolVarP(&write, "write", "w", false, "may this account write it")
	// On a directory this is traversal: passing through without being able to
	// list it, which is what an enrolment grants and what every path under a home
	// depends on.
	c.Flags().BoolVarP(&execute, "execute", "x", false,
		"may this account execute it, or traverse it where it is a directory")
	return c
}

// runAccess exits 0 where the access is permitted and 1 where it is not.
//
// Deny by default: no flag is a question nobody asked, and answering it yes
// would report a boundary as open on the strength of an empty command line.
// Several together is the conjunction, as access(2)'s own mask is.
func runAccess(path string, read, write, execute bool) int {
	var mode uint32
	if read {
		mode |= unix.R_OK
	}
	if write {
		mode |= unix.W_OK
	}
	if execute {
		mode |= unix.X_OK
	}
	if mode == 0 {
		fmt.Fprintln(os.Stderr, "faramir access: name --read, --write or --execute; "+
			"with none of them there is no question to answer")
		return 2
	}
	// Faccessat with a zero flags argument asks about the real uid and gid and
	// the process's supplementary groups, which under runuser are the account's.
	// Not AT_EACCESS: doctor asks what that account may do, and the effective ids
	// of this short-lived child are the same ones anyway.
	if err := unix.Faccessat(unix.AT_FDCWD, path, mode, 0); err != nil {
		return 1
	}
	return 0
}
