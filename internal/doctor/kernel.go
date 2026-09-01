package doctor

import (
	"os"
	"strings"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostunit"
)

// ptraceScopeFile is Yama's, and absent on a kernel built without it.
const ptraceScopeFile = "/proc/sys/kernel/yama/ptrace_scope"

// usernsSwitches are the kernel controls that decide whether an unprivileged
// account may create a user namespace, in the order they are looked for: the
// Ubuntu one is an AppArmor restriction and the Debian one a plain on/off, and
// a host has one or neither. A variable so a test can point at files it
// wrote.
var usernsSwitches = []struct {
	path string
	// open is the value that permits it: the Ubuntu file is a restriction, so 0
	// permits, and the Debian one is a permission, so 1 does.
	open string
	// shut is what to set it to, printed in the remedy.
	shut string
}{
	{"/proc/sys/kernel/apparmor_restrict_unprivileged_userns", "0", "1"},
	{"/proc/sys/kernel/unprivileged_userns_clone", "1", "0"},
}

// diagnoseUserns reports what the executor unit cannot bound.
// RestrictNamespaces= is a seccomp rule on clone()'s flags, and clone3() carries
// the same flags behind a pointer seccomp cannot read, so setting it at any
// value denies clone3() with ENOSYS; every brokered command is spawned with
// CLONE_INTO_CGROUP, which only clone3() has.
//
// So a brokered command can unshare a user namespace and hold a full capability
// set inside it. On the default install those capabilities have little to act
// on -- SystemCallFilter=@system-service denies the mount family, ProtectProc=
// masks procfs, and every boundary that matters is a uid the namespace maps
// only to itself. On a host installed with --allow-sudo the seccomp filter is
// gone by design and the mount family is reachable.
//
// Reported rather than enforced: this is a kernel-wide sysctl every other
// container and browser sandbox on the host depends on.
func diagnoseUserns(report *Report, opts Options, cfg *config.Config) {
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.addf("user namespaces", StatusNA, "no [sudo] section, so the executor unit carries "+
			"SystemCallFilter=@system-service, which excludes @mount: a namespace confers "+
			"capabilities with nothing to act on")
		return
	}
	for _, control := range usernsSwitches {
		raw, err := os.ReadFile(control.path)
		if err != nil {
			continue
		}
		value := strings.TrimSpace(string(raw))
		if value != control.open {
			report.addf("user namespaces", StatusOK, "%s is %s, so %s cannot unshare a "+
				"user namespace to hold capabilities in", control.path, value, opts.ExecUser)
			return
		}
		report.addf("user namespaces", StatusWarn, "%s is %s, so a brokered command may unshare a user namespace and hold a full "+
			"capability set inside it. The unit cannot refuse it: RestrictNamespaces= denies "+
			"clone3, which every run needs. The uid boundaries hold; what it reaches is "+
			"the mount family. Close it: sysctl -w %s=%s, and a line in /etc/sysctl.d",
			control.path, value, control.path, control.shut)
		return
	}
	report.unaskedf("user namespaces", 1, "this kernel exposes no switch for unprivileged user namespaces, so whether a "+
		"brokered command may unshare one was not asked. The unit cannot refuse it "+
		"either: RestrictNamespaces= denies clone3, which every run needs")
}

// diagnosePtraceScope checks what stands between a brokered command and the
// other processes of the executor's uid, on a host that grants an escalation.
// The executor daemon outlives every run, is in no run's cgroup, and receives
// each run's whole environment, so it can see every injected value. A process
// that can attach to a member of an approved run is inside that run as far as an
// escalation is concerned, ancestry being what attributes one.
//
// The daemons mark themselves undumpable, which refuses same-uid ptrace
// whatever this setting says; this check is about everything else of that uid.
// With ptrace_scope=0, the default on RHEL, Fedora and Arch, any process may
// attach to any other of the same uid, and the --allow-sudo executor unit
// carries no seccomp filter to refuse the syscall: a filter forces
// NoNewPrivileges= on, which makes sudo inert.
//
// A warning rather than a failure, being a host-wide sysctl other software has
// opinions about. N/a without a grant: that host's unit carries
// SystemCallFilter=@system-service, which excludes @ptrace.
func diagnosePtraceScope(report *Report, cfg *config.Config) {
	if cfg == nil || cfg.Sudo.ExecUser == "" {
		report.addf("ptrace scope", StatusNA, "no [sudo] section, so the executor unit carries "+
			"SystemCallFilter=@system-service, which excludes @ptrace: the syscall is refused "+
			"whatever %s says",
			ptraceScopeFile)
		return
	}
	raw, err := os.ReadFile(ptraceScopeFile)
	if err != nil {
		report.unaskedf("ptrace scope", 1, "%s cannot be read (%v), so whether one process running as %s can ptrace another "+
			"is unknown. On a host granting an escalation that decides whether a run's "+
			"processes are separate",
			ptraceScopeFile, err, cfg.Sudo.ExecUser)
		return
	}
	scope := strings.TrimSpace(string(raw))
	if scope == "0" {
		report.addf("ptrace scope", StatusWarn, "%s is 0, so any process running as %s may ptrace any other of that uid, and this "+
			"host grants an escalation. Set it to 1 or higher: sysctl -w "+
			"kernel.yama.ptrace_scope=1, and a line in /etc/sysctl.d", ptraceScopeFile, cfg.Sudo.ExecUser)
		return
	}
	report.addf("ptrace scope", StatusOK, "%s is %s, so one process running as %s "+
		"cannot attach to another that is not its own descendant",
		ptraceScopeFile, scope, cfg.Sudo.ExecUser)
}

// diagnoseCgroupDelegation checks the reaper every run depends on: the executor
// confines a brokered command to a cgroup of its own and tears the cgroup down
// when the run ends, so a setsid child cannot outlive it. That needs Delegate=
// on the unit, which `init` renders. There is no process-group fallback, so
// without it the executor refuses every command.
func diagnoseCgroupDelegation(report *Report, _ Options, _ *config.Config) {
	delegates, known := execUnitDelegates()
	switch {
	case !known:
		// systemd not reachable, or the unit not installed: the socket and broker
		// checks already speak to that.
		return
	case !delegates:
		report.addf("cgroup delegation", StatusFailed, "the executor unit does not set Delegate=, so it cannot confine a run and refuses "+
			"every brokered command. Reinstall with `faramir init` on a host running cgroup v2 "+
			"(kernel >= 5.14)")
	default:
		report.addf("cgroup delegation", StatusOK, "the executor unit is delegated a "+
			"cgroup subtree, so each run is confined and reaped and a setsid child "+
			"cannot outlive it")
	}
}

// execUnitDelegates reports whether the executor unit is granted its own cgroup
// subtree (Delegate=), and whether that could be determined. systemctl show
// reads the unit whether or not it is running, the executor being
// socket-activated and usually idle.
func execUnitDelegates() (delegates, known bool) {
	out, ok := hostunit.Property(hostunit.ExecUnit, "Delegate")
	return out == "yes", ok
}

// diagnoseProtectProc: all three units carry ProtectProc=invisible, which
// hides every other account's processes from the daemon; a drop-in or a hand
// edit that takes it off leaves that daemon reading a /proc it has no business
// seeing. Asked of systemd, which resolves drop-ins, rather than of the files.
//
// What this deliberately does not probe: another account reading a daemon's
// /proc/<pid>/environ. The kernel's own mode bits refuse that on every host
// whatever the unit says, so a probe there passes unconditionally and measures
// nothing; the e2e suite reads the boundary itself.
func diagnoseProtectProc(report *Report) {
	for _, unit := range []string{hostunit.BrokerUnit, hostunit.KeeperUnit, hostunit.ExecUnit} {
		value, ok := hostunit.Property(unit, "ProtectProc")
		if !ok {
			report.unaskedf("protectproc", 1, "systemd could not report %s's "+
				"ProtectProc, so it was not asked", unit)
			continue
		}
		if value != "invisible" {
			report.addf("protectproc", StatusFailed, "%s runs with ProtectProc=%s "+
				"rather than the invisible the install writes, so that daemon sees "+
				"every account's /proc. A drop-in or an edit took it off; `sudo "+
				"faramir init` writes the unit back", unit, value)
			continue
		}
		report.addf("protectproc", StatusOK, "%s hides other accounts' /proc", unit)
	}
}
