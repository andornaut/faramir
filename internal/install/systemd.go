package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// unitActive is what `systemctl is-active` prints for a unit that is up.  Every
// other word it prints is one of the states this treats as down.
const unitActive = "active"

// services in restart order.  The keeper leads: it decrypts the file list the
// broker is served, so the other order fetches the old value set again.
var services = []string{
	"faramir-keeper.service",
	"faramir-exec.service",
	"faramir-broker.service",
}

// systemdRunning reports whether there is a systemd to talk to.  A container or
// image build has none, and the units are still worth installing there.
//
// A variable so a test can answer for it, as loginDefs and shadowFile are: what
// needs covering is the branch taken on a host WITHOUT systemd, and a test
// running on one that has it cannot reach that any other way.
var systemdRunning = func() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// systemUnitDir is where the units are installed.  A variable so a test can
// point at a directory it wrote, as loginDefs and shadowFile are.
var systemUnitDir = "/etc/systemd/system"

// UnitPath is where a unit of this name is installed.  Exported so a caller
// outside this package resolves the same file this one does, rather than
// restating the directory and drifting from it.
func UnitPath(name string) string {
	return filepath.Join(systemUnitDir, name)
}

// unitUser reads User= out of an installed unit.  Parsed rather than asked of
// systemctl, which reports the running unit and answers nothing when the daemon
// is down, which is one of the states worth examining.
func unitUser(name string) (string, error) {
	path := UnitPath(name)
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		if account, ok := strings.CutPrefix(strings.TrimSpace(line), "User="); ok {
			if account = strings.TrimSpace(account); account != "" {
				return account, nil
			}
		}
	}
	return "", fmt.Errorf("%s names no User=", path)
}

// UnitConfigFile is the config file the unit at this path loads, or "" when
// there is no unit or it names none.  Read from the unit rather than asked of a
// running broker: a host whose daemons are down still has an install, and this
// is the question of where that install is.
//
// Drop-ins as well as the unit, in the order systemd reads them: a
// <unit>.d/*.conf setting Environment=FARAMIR_CONFIG is what the daemons
// actually load, and uninstall removes those directories, so they are a state
// this install expects rather than one only an operator could have made.
// Reading the main file alone would see no move where there is one, and
// re-provision a directory nothing loads.
//
// Exported because every caller that resolves this host's install has to get
// the same answer: one reader consulting drop-ins and another reading the unit
// alone put init's own refusal at odds with the directory it was given.
func UnitConfigFile(unit string) string {
	file := ""
	for _, path := range unitFiles(unit) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line),
				"Environment=FARAMIR_CONFIG="); ok {
				// An empty assignment is systemd's way of unsetting, so it clears what an
				// earlier file said rather than being skipped as "names none".
				file = strings.TrimSpace(value)
			}
		}
	}
	return file
}

// unitConfigDir is UnitConfigFile's directory, for the installed unit of this
// name.
func unitConfigDir(name string) string {
	file := UnitConfigFile(UnitPath(name))
	if file == "" {
		return ""
	}
	return filepath.Dir(file)
}

// unitFiles is a unit and its drop-ins, in the order systemd applies them: the
// unit first, then <unit>.d/*.conf sorted by name, later winning.
func unitFiles(unit string) []string {
	files := []string{unit}
	entries, err := os.ReadDir(unit + ".d")
	if err != nil {
		return files
	}
	var dropIns []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			dropIns = append(dropIns, filepath.Join(unit+".d", entry.Name()))
		}
	}
	slices.Sort(dropIns)
	return append(files, dropIns...)
}

func (r *runner) stepSystemd() error {
	if r.opts.DryRun {
		r.skip("systemd", "dry run")
		return nil
	}
	if !systemdRunning() {
		r.warnf("systemd is not running here; the units are installed but nothing " +
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
		r.warnf("%s does not exist, so the services are installed but not "+
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
			if err != nil || strings.TrimSpace(out) != unitActive {
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
//
// The config is loaded before anything is stopped.  Reload's own act is to stop
// the services and leave the sockets listening, so a config the daemons cannot
// load is not found here at all: it is found by the first brokered command,
// which connects to a socket systemd is holding open and waits on a service
// that never becomes ready.  Refusing here leaves the running daemons serving
// the configuration they already have, which is the one thing that still works.
//
// --parse-only rather than --check: the question is whether the daemons can
// load this, not whether every managed value can be read.  --check also fails
// for a ref shorter than [secrets] min_length, which is a value to lengthen
// rather than a reason to refuse a restart.
// parseInstalledConfig asks the broker's own uid whether the installed config
// loads, which is the account that will have to load it.
func parseInstalledConfig(run *runner) error {
	unit := UnitPath("faramir-broker.service")
	configFile := UnitConfigFile(unit)
	if configFile == "" {
		configFile = filepath.Join(DefaultConfigDir, "config.toml")
	}
	brokerUser, err := unitUser(filepath.Base(unit))
	if err != nil {
		// No unit to read means nothing is installed to reload; leave that to the
		// systemctl calls, which name it better than a guess here would.
		return nil //nolint:nilerr // nothing installed is not a parse failure
	}
	out, err := run.command("runuser", "-u", brokerUser, "--",
		filepath.Join(DefaultBinDir, "faramir"), "broker", "-c", configFile, "--parse-only")
	if err != nil {
		return fmt.Errorf("%s does not load as %s, so nothing was stopped and the "+
			"daemons are still serving what they already have: %w\n%s",
			configFile, brokerUser, err, strings.TrimSpace(out))
	}
	return nil
}

func Reload() error {
	if !systemdRunning() {
		return errors.New("systemd is not running here")
	}
	run := &runner{}
	if err := parseInstalledConfig(run); err != nil {
		return err
	}
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
