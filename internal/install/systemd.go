package install

import (
	"fmt"
	"os"
	"strings"
)

// sockets are what gets enabled, not services: all three are socket activated,
// so nothing starts before the operator has logged in, which is what makes a
// config or secrets inside a home workable.  The keeper and the executor first,
// the broker talking to both.
var sockets = []string{
	"faramir-keeper.socket",
	"faramir-exec.socket",
	"faramir-broker.socket",
}

// services in restart order.  The keeper leads: it decrypts the file list the
// broker is served, so the other order fetches the old value set again.
var services = []string{
	"faramir-keeper.service",
	"faramir-exec.service",
	"faramir-broker.service",
}

// systemdRunning reports whether there is a systemd to talk to.  A container or
// image build has none, and the units are still worth installing there.
func systemdRunning() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

func (r *runner) stepSystemd() error {
	if r.opts.DryRun {
		r.skip("systemd", "dry run")
		return nil
	}
	if !systemdRunning() {
		r.warn("systemd is not running here; the units are installed but nothing " +
			"has been started")
		r.skip("systemd", "not running")
		return nil
	}
	if _, err := r.command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := r.command("systemd-tmpfiles", "--create", "/etc/tmpfiles.d/faramir.conf"); err != nil {
		return err
	}
	// The keeper reads the age key at startup and exits without one.
	if !exists(r.layout.AgeKeyPath) {
		r.warn("%s does not exist, so the services are installed but not "+
			"started", r.layout.AgeKeyPath)
		r.skip("systemd", "no age key")
		return nil
	}
	if _, err := r.command("systemctl", append([]string{"enable", "--now"}, sockets...)...); err != nil {
		return err
	}

	// Only when something the daemons read has changed: a restart kills every
	// brokered command in flight.  A socket that is not up counts, a unit left
	// inactive by an earlier failure being worth saying.
	restart := r.needsRestart
	if !restart {
		for _, socket := range sockets {
			out, err := r.command("systemctl", "is-active", socket)
			if err != nil || strings.TrimSpace(out) != "active" {
				restart = true
				break
			}
		}
	}
	if restart {
		// Restart, not enable --now: an already-active socket keeps whatever
		// ownership its file was left with.
		if _, err := r.command("systemctl", append([]string{"restart"}, sockets...)...); err != nil {
			return err
		}
		for _, service := range services {
			if _, err := r.command("systemctl", "restart", service); err != nil {
				return err
			}
		}
	}
	// systemd ignores a directive it does not recognise and starts the unit
	// anyway, so a misspelled hardening key is silent.  verify exits 0 either
	// way, so the output is what is checked.
	for _, service := range services {
		out, _ := r.commandCombined("systemd-analyze", "verify", service)
		for line := range strings.Lines(out) {
			// verify reports on everything the unit pulls in transitively, so
			// an unrelated unit's typo would otherwise abort the install.
			if !strings.Contains(line, service) {
				continue
			}
			if strings.Contains(line, "Unknown key name") {
				return fmt.Errorf("systemd does not recognise a directive in %s and "+
					"ignores it rather than failing: %s. A hardening or credential "+
					"setting that is silently dropped leaves the daemon running and "+
					"holding nothing", service, strings.TrimSpace(line))
			}
		}
	}
	detail := "already running what is installed"
	if restart {
		detail = "restarted onto the new " + strings.Join(r.restartReasons, ", ")
	}
	r.step("systemd", restart, detail)
	return nil
}

// Reload drops the daemons onto a changed configuration.  Exported because a
// consumer writes its own config.d drop-in, and none of the daemons re-reads
// its config while running.
func Reload() error {
	if !systemdRunning() {
		return fmt.Errorf("systemd is not running here")
	}
	run := &runner{}
	if _, err := run.command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Stop rather than restart: all three are socket activated, so the next
	// brokered command starts them on the new config, in the order activation
	// supplies.
	if _, err := run.command("systemctl", append([]string{"stop"}, services...)...); err != nil {
		return err
	}
	// The sockets are what activates them again; already listening is a
	// no-op.
	if _, err := run.command("systemctl", append([]string{"start"}, sockets...)...); err != nil {
		return err
	}
	return nil
}
