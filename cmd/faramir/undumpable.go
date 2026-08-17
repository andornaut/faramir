package main

// PR_SET_DUMPABLE=0 on the two daemons that hold something.
//
// Both matter for the same reason and one of them matters twice.
//
// The executor daemon runs as the uid every brokered command runs as, and it is
// not in any run's cgroup: it is the one process of that uid that outlives
// every run by construction.  It also receives each run's whole environment over
// its socket, which is FARAMIR_ESCALATION_TOKEN and every injected value, so it is
// the single place every run's token can be read from at once.  A brokered
// command is therefore a same-uid process sitting beside the most interesting
// process on the host, with nothing between them but the kernel's rules about
// ptrace: /proc/sys/kernel/yama/ptrace_scope is 1 on Debian and Ubuntu, which
// permits only descendants, and 0 on RHEL, Fedora and Arch, which permits any
// process of the same uid.  On a host installed with --allow-sudo the executor
// unit carries no seccomp filter at all.  It cannot: a filter forces
// NoNewPrivileges= on, and that makes sudo inert.  So nothing else refuses the
// syscall either.
//
// The broker holds every decrypted value and the SSH agent.  Nothing runs as its
// uid but itself, so this is defence in depth there rather than a boundary.
//
// Dumpable=0 refuses same-uid ptrace whatever ptrace_scope says, and reparents
// /proc/self to root:root so the same uid cannot read the process's environ or
// memory either.  The cost is core dumps from either daemon, which handle
// plaintext and should not be producing one anyway.
//
// Not a substitute for `faramir doctor` failing a host with ptrace_scope=0: this
// covers these two processes, and that setting is about every other one.

import (
	"log"

	"golang.org/x/sys/unix"
)

func undumpable(who string) {
	if err := unix.Prctl(unix.PR_SET_DUMPABLE, 0, 0, 0, 0); err != nil {
		// Reported rather than fatal: what this protects is one process from
		// another of its own uid, and refusing to start would take the whole role
		// down over a hardening measure.  A host where it fails is one to look at.
		log.Printf("%s could not mark itself undumpable (%v), so a process of its own "+
			"uid may be able to ptrace it or read its memory", who, err)
	}
}
