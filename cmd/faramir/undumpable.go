package main

// PR_SET_DUMPABLE=0 on the two daemons that hold something.
//
// The executor daemon runs as the uid every brokered command runs as, is in no
// run's cgroup, and receives each run's whole environment over its socket, so
// it is the one place every run's escalation token can be read from at once.
// What stands between it and a brokered command is ptrace_scope, which is 1 on
// Debian and Ubuntu and 0 on RHEL, Fedora and Arch; on a host installed with
// --allow-sudo the executor unit carries no seccomp filter either, a filter
// forcing NoNewPrivileges= on and making sudo inert.
//
// The broker holds every decrypted value and the SSH agent.  Nothing runs as
// its uid but itself, so this is defence in depth there.
//
// Dumpable=0 refuses same-uid ptrace whatever ptrace_scope says, and reparents
// /proc/self to root:root so the same uid cannot read the process's environ or
// memory.  The cost is core dumps from either daemon, which handle plaintext.
// Not a substitute for `faramir doctor` failing a host with ptrace_scope=0:
// that setting is about every other process.

import (
	"log"

	"golang.org/x/sys/unix"
)

func undumpable(who string) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		// Reported rather than fatal: refusing to start would take the whole role
		// down over a hardening measure.
		log.Printf("%s could not mark itself undumpable (%v), so a process of its own "+
			"uid may be able to ptrace it or read its memory", who, err)
	}
}
