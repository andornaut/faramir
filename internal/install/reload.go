package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/runcmd"
)

func (r *runner) stepSystemd() error {
	if r.opts.DryRun {
		r.skip("systemd", "dry run")
		return nil
	}
	if !hostunit.Running() {
		r.warnf("systemd is not running here; the units are installed but nothing " +
			"has been started")
		r.skip("systemd", "not running")
		return nil
	}
	if _, err := runcmd.Output("systemctl", "daemon-reload"); err != nil {
		return err
	}
	if _, err := runcmd.Output("systemd-tmpfiles", "--create", "/etc/tmpfiles.d/faramir.conf"); err != nil {
		return err
	}
	// The keeper reads the age key at startup and exits without one.
	if !hostfs.Exists(r.layout.AgeKeyPath) {
		r.warnf("%s does not exist, so the services are installed but not "+
			"started", r.layout.AgeKeyPath)
		r.skip("systemd", "no age key")
		return nil
	}
	if _, err := runcmd.Output("systemctl", append([]string{"enable", "--now"}, hostunit.Sockets...)...); err != nil {
		return err
	}

	// Only when something the daemons read has changed: a restart kills every
	// brokered command in flight. A socket that is not up counts too.
	restart := r.needsRestart
	if !restart {
		for _, socket := range hostunit.Sockets {
			out, err := runcmd.Output("systemctl", "is-active", socket)
			if err != nil || strings.TrimSpace(out) != hostunit.Active {
				restart = true
				break
			}
		}
	}
	if restart {
		// Restart, not enable --now: an already-active socket keeps whatever
		// ownership its file was left with.
		if _, err := runcmd.Output("systemctl", append([]string{"restart"}, hostunit.Sockets...)...); err != nil {
			return err
		}
		for _, service := range hostunit.Services {
			if _, err := runcmd.Output("systemctl", "restart", service); err != nil {
				return err
			}
		}
	}
	// systemd ignores a directive it does not recognise and starts the unit
	// anyway, so a misspelled hardening key is silent. verify exits 0 either
	// way, so the output is what is checked.
	for _, service := range hostunit.Services {
		out, _ := runcmd.Combined("systemd-analyze", "verify", service)
		for line := range strings.Lines(out) {
			// verify reports on everything the unit pulls in transitively, so an
			// unrelated unit's typo would otherwise abort the install.
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

// parseInstalledConfig asks the broker's own uid whether the installed config
// loads, which is the account that will have to load it.
//
// --parse-only rather than --check: the question is whether the daemons can
// load this, not whether every managed value can be read. --check also fails
// for a ref shorter than [secret] min_length, which is a value to lengthen
// rather than a reason to refuse a restart.
func parseInstalledConfig() error {
	unit := hostunit.Path(hostunit.BrokerUnit)
	configFile := hostunit.ConfigFile(unit)
	if configFile == "" {
		configFile = filepath.Join(hostlayout.DefaultConfigDir, "config.toml")
	}
	brokerUser, err := hostunit.User(filepath.Base(unit))
	if err != nil {
		// No unit to read means nothing is installed to reload; leave that to the
		// systemctl calls, which name it better.
		return nil //nolint:nilerr // nothing installed is not a parse failure
	}
	// FARAMIR_CONFIG rather than a flag: no faramir command takes a config path,
	// and runuser clears the environment, so the variable has to be set on the
	// far side of it. The same variable the units give the daemons.
	out, err := runcmd.Output("runuser", "-u", brokerUser, "--",
		"env", "FARAMIR_CONFIG="+configFile,
		filepath.Join(hostlayout.DefaultBinDir, "faramir"), "broker", "--parse-only")
	if err != nil {
		return fmt.Errorf("%s does not load as %s, so nothing was stopped and the "+
			"daemons are still serving what they already have: %w\n%s",
			configFile, brokerUser, err, strings.TrimSpace(out))
	}
	return nil
}

// Reload drops the daemons onto a changed configuration. Exported because
// `faramir link` changes the config too, and none of the daemons re-reads its
// config while running.
//
// The config is parsed before anything is stopped: Reload stops the services
// and leaves the sockets listening, so a config the daemons cannot load would
// otherwise be found by the first brokered command, waiting on a service that
// never becomes ready. Refusing here leaves the running daemons serving the
// configuration they already have.
func Reload() error {
	if !hostunit.Running() {
		return errors.New("systemd is not running here")
	}
	if err := parseInstalledConfig(); err != nil {
		return err
	}
	if _, err := runcmd.Output("systemctl", "daemon-reload"); err != nil {
		return err
	}
	// Stop rather than restart: all three are socket activated, so the next
	// brokered command starts them on the new config.
	if _, err := runcmd.Output("systemctl", append([]string{"stop"}, hostunit.Services...)...); err != nil {
		return err
	}
	// The sockets are what activates them again; already listening is a no-op.
	if _, err := runcmd.Output("systemctl", append([]string{"start"}, hostunit.Sockets...)...); err != nil {
		return err
	}
	return nil
}
