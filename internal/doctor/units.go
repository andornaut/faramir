package doctor

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/runcmd"
)

// unitUnreportable is systemctl itself failing to answer, which is a subject
// out of reach rather than a state.
const unitUnreportable = "unreportable"

// SampleSockets is each socket unit's state now. Called before anything opens
// the broker socket; see [Options.SocketStates].
func SampleSockets() map[string]string {
	if !hostunit.Running() {
		return nil
	}
	states := make(map[string]string, len(hostunit.Sockets))
	for _, socket := range hostunit.Sockets {
		state, ok := hostunit.State(socket)
		if !ok {
			state = unitUnreportable
		}
		states[socket] = state
	}
	return states
}

// diagnoseUnits reports the sockets, not the services: all three are socket
// activated, so an inactive service is ordinary.
func diagnoseUnits(report *Report, opts Options) {
	if !hostunit.Running() {
		report.unaskedf("sockets", len(hostunit.Sockets), "systemd not running; "+
			"%d socket unit(s) not checked", len(hostunit.Sockets))
		return
	}
	// What the caller saw before it opened the broker socket. Reading the state
	// here would read it after that round trip, which starts any socket the broker
	// depends on, so all three would report as listening.
	states := opts.SocketStates
	if len(states) == 0 {
		states = SampleSockets()
	}
	for _, socket := range hostunit.Sockets {
		state, sampled := states[socket]
		if !sampled {
			state = unitUnreportable
		}
		// systemctl failing to answer is a subject this could not reach, not a
		// socket known to be down: failing would point an operator at a
		// journalctl that fails the same way.
		if state == unitUnreportable {
			report.unaskedf("sockets", 1, "systemctl could not report %s", socket)
			continue
		}
		if state != hostunit.Active {
			report.addf("sockets", StatusFailed, "%s is %s; check `journalctl -u %s`",
				socket, state, socket)
			continue
		}
		report.addf("sockets", StatusOK, "%s is listening", socket)
	}
}

// diagnoseSocketEnablement: enabled as well as active. A socket somebody
// disabled keeps listening until the next reboot, which is when nothing starts
// and every brokered command meets a dead socket with nothing in this report
// having said so.
func diagnoseSocketEnablement(report *Report) {
	if !hostunit.Running() {
		return
	}
	for _, socket := range hostunit.Sockets {
		out, err := runcmd.OutputWithin(30*time.Second, "systemctl", "is-enabled", socket)
		state := strings.TrimSpace(out)
		// is-enabled exits non-zero for disabled while still printing the state;
		// only an empty answer is systemctl failing.
		if state == "" {
			if err != nil {
				report.unaskedf("sockets", 1, "systemctl could not report whether "+
					"%s is enabled", socket)
			}
			continue
		}
		if state != "enabled" {
			report.addf("sockets", StatusWarn, "%s is %s, not enabled at boot; "+
				"run `sudo systemctl enable %s`", socket, state, socket)
		}
	}
}

// diagnoseDropIns names any drop-in overriding a faramir unit: a
// units.d/override.conf can change User=, drop ProtectSystem= or repoint the
// config, and until now nothing in this report said a file did it. Warned, not
// failed: a drop-in is the operator's own arrangement, and what this buys is
// that it is named next to the checks that read the resolved values.
func diagnoseDropIns(report *Report) {
	if !hostunit.Running() {
		return
	}
	var dropIns []string
	for _, unit := range slices.Concat(hostunit.Services, hostunit.Sockets) {
		if paths, ok := hostunit.Property(unit, "DropInPaths"); ok && paths != "" {
			dropIns = append(dropIns, unit+" ("+paths+")")
		}
	}
	if len(dropIns) == 0 {
		report.addf("unit drop-ins", StatusOK, "no drop-in overrides a faramir unit")
		return
	}
	report.addf("unit drop-ins", StatusWarn, "%d faramir unit(s) overridden by a drop-in\n%s",
		len(dropIns), strings.Join(dropIns, "\n"))
}

// gib renders a byte count the way an operator sizes one of these: the config
// key is in MB and the unit resolves to bytes, and neither reads at a glance.
func gib(bytes int64) string {
	return fmt.Sprintf("%.1f GB", float64(bytes)/(1<<30))
}

// diagnoseMemoryBounds reads what the executor unit's two memory limits resolve
// to and reports when the per-process one is out of reach.
//
// They answer different questions and are sized against different things, so
// nothing stops an operator setting a per-process bound above the cgroup total.
// Where that happens the cgroup is met first and the OOM killer picks a victim,
// which is the outcome the per-process bound was chosen over: it hands the
// process an allocation failure it can report instead. The defaults cross on a
// host with less memory than four times the percentage, so a laptop reaches
// this without anybody configuring anything.
//
// Read from systemd rather than computed from the config: the percentage
// resolves against the cgroup's own limit, which inside a container is the
// container's and not the machine's, and only systemd knows which.
func diagnoseMemoryBounds(report *Report) {
	const check = "memory bounds"
	if !hostunit.Running() {
		report.unaskedf(check, 1, "systemd not running; executor limits not checked")
		return
	}
	maxMemory, haveMax := hostunit.Int(hostunit.ExecUnit, "MemoryMax")
	perProcess, havePer := hostunit.Int(hostunit.ExecUnit, "LimitDATA")
	reportMemoryBounds(report, perProcess, havePer, maxMemory, haveMax)
}

// reportMemoryBounds is the verdict on two resolved limits, apart from reading
// them so the judgement can be asserted without systemd.
func reportMemoryBounds(report *Report, perProcess int64, havePer bool,
	maxMemory int64, haveMax bool) {
	const check = "memory bounds"
	switch {
	case !haveMax && !havePer:
		report.addf(check, StatusWarn, "%s sets no MemoryMax or LimitDATA; "+
			"run `sudo faramir init` to write both", hostunit.ExecUnit)
	case !havePer:
		report.addf(check, StatusWarn, "%s sets MemoryMax %s and no LimitDATA; "+
			"run `sudo faramir init` to write it", hostunit.ExecUnit, gib(maxMemory))
	case !haveMax:
		// The cgroup total is the half that catches fan-out, which no per-process
		// bound sees, so its absence is the condition this check exists for.
		report.addf(check, StatusWarn, "%s sets LimitDATA %s and no MemoryMax; "+
			"run `sudo faramir init` to write it", hostunit.ExecUnit, gib(perProcess))
	case perProcess >= maxMemory:
		report.addf(check, StatusWarn, "per-process limit %s is not below the "+
			"executor's %s; set [command] max_process_memory_mb below %d, then run "+
			"`sudo faramir init`",
			gib(perProcess), gib(maxMemory), maxMemory/(1<<20))
	default:
		report.addf(check, StatusOK, "%s per process, %s in all",
			gib(perProcess), gib(maxMemory))
	}
}

// diagnoseBrokerMemory reports what the broker is holding against what it is
// allowed to hold. The broker's memory is the size of the value set rather than
// a property of the code -- the automaton it scans with costs roughly 15 KB per
// byte of secret -- so this grows as the store does, and it is met by an
// operator who added secrets rather than by a bug.
//
// Read from systemd for the same reason the executor's is: the percentage
// resolves against the cgroup's own limit, which inside a container is the
// container's and not the machine's.
func diagnoseBrokerMemory(report *Report) {
	const check = "broker memory"
	if !hostunit.Running() {
		report.unaskedf(check, 1, "systemd not running; broker limit not checked")
		return
	}
	limit, haveLimit := hostunit.Int(hostunit.BrokerUnit, "MemoryMax")
	used, haveUsed := hostunit.Int(hostunit.BrokerUnit, "MemoryCurrent")
	reportBrokerMemory(report, used, haveUsed, limit, haveLimit)
}

// reportBrokerMemory is the verdict on the two, apart from reading them so the
// judgement can be asserted without systemd.
func reportBrokerMemory(report *Report, used int64, haveUsed bool,
	limit int64, haveLimit bool) {
	const check = "broker memory"
	// The share at which a store is close enough to the ceiling to say so: past
	// it, adding a few more secrets is what meets it.
	const crowded = 80
	switch {
	// A drop-in may set MemoryMax=0, which parses as a number and is a broker
	// that may hold nothing. Answered before the share below, which would
	// divide by it.
	case haveLimit && limit == 0:
		report.addf(check, StatusFailed, "%s sets MemoryMax=0; remove that "+
			"drop-in, or run `sudo faramir init`", hostunit.BrokerUnit)
	case !haveLimit:
		report.addf(check, StatusWarn, "%s sets no MemoryMax; run `sudo faramir "+
			"init` to write it", hostunit.BrokerUnit)
	case !haveUsed:
		report.addf(check, StatusOK, "limit %s", gib(limit))
	case used*100/limit >= crowded:
		report.addf(check, StatusWarn, "broker uses %s of its %s limit; remove "+
			"secrets from the store, or add memory", gib(used), gib(limit))
	default:
		report.addf(check, StatusOK, "%s of %s", gib(used), gib(limit))
	}
}
