package install

import (
	"fmt"
	"os"
	"strings"
)

// sockets are what gets enabled.  Sockets, not services: all three are socket
// activated, so nothing tries to start before the operator has logged in, which
// is what makes a config or a store inside a home workable at all.
//
// The keeper and the executor before the broker, which talks to both.
var sockets = []string{
	"faramir-keeper.socket",
	"faramir-exec.socket",
	"faramir-broker.socket",
}

// services in the order they have to be restarted.  The keeper leads: it
// decrypts the file list the broker is then served, so restarting the broker
// first only fetches the old value set again.
var services = []string{
	"faramir-keeper.service",
	"faramir-exec.service",
	"faramir-broker.service",
}

// systemdRunning reports whether there is a systemd to talk to.  A container,
// chroot or image build has none, and the units are still worth installing
// there; what must not happen is pretending to have started something.
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
	// The keeper reads the age key at startup and exits without one, so there
	// is nothing to start yet.  Not an error: --seal-age-key with the plaintext
	// already removed is a legitimate way to reach this.
	if !exists(r.layout.AgeKeyPath) && !exists(r.layout.AgeKeyCred) {
		r.warn("neither %s nor %s exists, so the services are installed but not "+
			"started", r.layout.AgeKeyPath, r.layout.AgeKeyCred)
		r.skip("systemd", "no age key")
		return nil
	}
	if _, err := r.command("systemctl", append([]string{"enable", "--now"}, sockets...)...); err != nil {
		return err
	}
	// Restart, not just enable --now: an already-active socket keeps whatever
	// ownership its file was left with, and the services below have to pick up
	// the new listeners anyway.
	if _, err := r.command("systemctl", append([]string{"restart"}, sockets...)...); err != nil {
		return err
	}
	for _, service := range services {
		if _, err := r.command("systemctl", "restart", service); err != nil {
			return err
		}
	}
	// systemd ignores a directive it does not recognise, logs one line and
	// starts the unit anyway, so a misspelled hardening or credential key is
	// silent until something needs what it was supposed to provide.  verify
	// exits 0 either way, so the output is what is checked.
	for _, service := range services {
		out, _ := r.commandCombined("systemd-analyze", "verify", service)
		for line := range strings.Lines(out) {
			// Only lines naming the unit being verified.  verify reports on
			// everything the unit pulls in transitively, so an unrelated
			// third-party unit with a misspelled directive would otherwise abort
			// the install blaming a faramir service.
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
	r.step("systemd", true, strings.Join(sockets, ", "))
	return nil
}

// Reload restarts the daemons onto a changed configuration.
//
// Exported because a consumer of the broker writes its own config.d drop-in and
// then has to get the daemons onto it, and the order is not obvious: neither
// re-reads its config while running, and the keeper has to lead because it
// decrypts the file list the broker is served.
func Reload() error {
	if !systemdRunning() {
		return fmt.Errorf("systemd is not running here")
	}
	run := &runner{}
	if _, err := run.command("systemctl", "daemon-reload"); err != nil {
		return err
	}
	for _, service := range services {
		if _, err := run.command("systemctl", "restart", service); err != nil {
			return err
		}
	}
	return nil
}
