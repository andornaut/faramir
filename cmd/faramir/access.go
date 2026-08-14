package main

// faramir access: answer access(2) for the account this process is already
// running as, and exit 0 or 1.
//
// `faramir doctor` asks whether an account can read or write a path, and the
// only honest way to ask is to be that account: access(2) answers for the
// calling process, and supplementary groups are per-process, so root cannot put
// the question on somebody else's behalf and no in-process trick covers the
// group case.  doctor therefore runs something under `runuser -u ACCOUNT`, and
// this is what it runs.
//
// It used to run the host's `test -r` / `test -w`.  That is a dependency on
// whatever coreutils the distribution shipped, and Ubuntu 25.10 replaced GNU
// coreutils with uutils, whose `test` ignores supplementary group membership:
// on a file that is root:dev 0660, asked as an account whose membership of dev
// is what grants it, it answers no.  Every group-based finding was then wrong,
// in both directions: a socket the client group reaches reported as closed to
// it, and a boundary that group membership had actually opened reported as
// holding.
//
// A subcommand of faramir's own rather than a shell builtin, which is also
// correct: `sh -c "test -w PATH"` puts a shell between doctor and the question,
// and these paths come from --ssh-key and the config, so it would need quoting
// that a root process must not get wrong.  argv carries a path with no
// interpretation.

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
)

// newAccessCmd answers one question about one path.  Internal: it is what
// doctor runs as another account, and an operator asking whether they can read
// a file has `test` for that.
func newAccessCmd() *cobra.Command {
	var (
		read  bool
		write bool
	)
	c := &cobra.Command{
		Use:     "access [options] PATH",
		Short:   "answer access(2) as this process's own account (run by doctor)",
		GroupID: groupInternal,
		Args: func(c *cobra.Command, args []string) error {
			if len(args) != 1 {
				return usagef("faramir access: one path is required")
			}
			return nil
		},
		RunE: func(c *cobra.Command, args []string) error {
			return codeErr(runAccess(args[0], read, write))
		},
	}
	c.Flags().BoolVarP(&read, "read", "r", false, "may this account read it")
	c.Flags().BoolVarP(&write, "write", "w", false, "may this account write it")
	return c
}

// runAccess exits 0 where the access is permitted and 1 where it is not.
//
// Deny by default: neither flag is a question nobody asked, and answering it
// yes would report a boundary as open on the strength of an empty command line.
// Both together is the conjunction, as access(2)'s own mask is.
func runAccess(path string, read, write bool) int {
	var mode uint32
	if read {
		mode |= unix.R_OK
	}
	if write {
		mode |= unix.W_OK
	}
	if mode == 0 {
		fmt.Fprintln(os.Stderr, "faramir access: name --read or --write; "+
			"with neither there is no question to answer")
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
