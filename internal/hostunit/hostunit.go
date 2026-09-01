// Package hostunit names faramir's systemd units and reads what an installed
// one says.
//
// The unit files are parsed rather than asked of systemctl, which answers
// nothing when the daemon is down, and a host whose daemons are down still has
// an install worth examining. Drop-ins are read with the unit, in the order
// systemd applies them, so a <unit>.d/*.conf that renamed an account is what
// answers rather than what the template shipped.
//
// It installs nothing and starts nothing: writing the units and restarting them
// is internal/install's.
package hostunit

import (
	"cmp"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/runcmd"
)

// BrokerUnit, KeeperUnit and ExecUnit name the three units once: several tables
// key on them and systemctl is handed them verbatim, so a rename that reached
// only some would leave a daemon nobody restarts.
const (
	BrokerUnit = "faramir-broker.service"
	KeeperUnit = "faramir-keeper.service"
	ExecUnit   = "faramir-exec.service"
)

// Sockets are what gets enabled, not services: all three are socket activated,
// so nothing starts before the operator has logged in, which is what makes a
// config or secrets inside a home workable. The keeper and the executor first,
// the broker talking to both.
var Sockets = []string{
	"faramir-keeper.socket",
	"faramir-exec.socket",
	"faramir-broker.socket",
}

// Active is what `systemctl is-active` prints for a unit that is up; every
// other word it prints counts as down.
const Active = "active"

// Services in restart order. The keeper leads: it decrypts the file list the
// broker is served, so the other order fetches the old value set again.
var Services = []string{
	KeeperUnit,
	ExecUnit,
	BrokerUnit,
}

// Running reports whether there is a systemd to talk to. A container or
// image build has none, and the units are still worth installing there. A
// variable so a test can answer for it: the branch taken on a host without
// systemd is unreachable from one that has it.
var Running = func() bool {
	info, err := os.Stat("/run/systemd/system")
	return err == nil && info.IsDir()
}

// SystemUnitDir is where the units are installed. A variable so a test can
// point at a directory it wrote.
var SystemUnitDir = "/etc/systemd/system"

// Path is where a unit of this name is installed. Exported so a caller
// outside this package resolves the same file this one does.
func Path(name string) string {
	return filepath.Join(SystemUnitDir, name)
}

// User reads User= out of an installed unit. Parsed rather than asked of
// systemctl, which answers nothing when the daemon is down, which is one of the
// states worth examining.
//
// The drop-ins with it, and the last assignment winning, which is how systemd
// resolves the pair: a `.d/*.conf` naming another account is how a host renames
// one without editing a file the install rewrites. Reading the main unit alone
// reported the name the template shipped, and a caller refusing service accounts
// as operators would then not refuse the account the executor actually runs as.
//
// An empty assignment is systemd's way of unsetting, so it clears what an
// earlier file said rather than being passed over, as UnitConfigFile treats one.
func User(name string) (string, error) {
	unit := Path(name)
	account := ""
	read := false
	for _, path := range files(unit) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		read = true
		for line := range strings.SplitSeq(string(body), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line), "User="); ok {
				account = strings.TrimSpace(value)
			}
		}
	}
	switch {
	case !read:
		// The unit itself is what a caller cannot read, so the error is that file's
		// rather than a drop-in's: an absent unit is an install that is not there.
		_, err := os.ReadFile(unit)
		return "", err
	case account == "":
		return "", fmt.Errorf("%s names no User=", unit)
	}
	return account, nil
}

// ConfigFile is the config file the unit at this path loads, or "" when
// there is no unit or it names none. Read from the unit rather than asked of a
// running broker: a host whose daemons are down still has an install.
//
// Drop-ins as well as the unit, in the order systemd reads them: a
// <unit>.d/*.conf setting Environment=FARAMIR_CONFIG is what the daemons load,
// so reading the main file alone would see no move where there is one.
//
// Exported because every caller that resolves this host's install has to get
// the same answer.
func ConfigFile(unit string) string {
	file := ""
	for _, path := range files(unit) {
		body, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		for line := range strings.SplitSeq(string(body), "\n") {
			if value, ok := strings.CutPrefix(strings.TrimSpace(line),
				"Environment=FARAMIR_CONFIG="); ok {
				// An empty assignment is systemd's way of unsetting, so it clears what
				// an earlier file said rather than being skipped as "names none".
				file = strings.TrimSpace(value)
			}
		}
	}
	return file
}

// ConfigDir is UnitConfigFile's directory, for the installed unit of this
// name.
func ConfigDir(name string) string {
	file := ConfigFile(Path(name))
	if file == "" {
		return ""
	}
	return filepath.Dir(file)
}

// files is a unit and its drop-ins, in the order systemd applies them: the
// unit first, then <unit>.d/*.conf sorted by name, later winning.
func files(unit string) []string {
	entries, err := os.ReadDir(unit + ".d")
	if err != nil {
		return []string{unit}
	}
	var dropIns []string
	for _, entry := range entries {
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".conf") {
			dropIns = append(dropIns, filepath.Join(unit+".d", entry.Name()))
		}
	}
	slices.Sort(dropIns)
	files := make([]string, 0, 1+len(dropIns))
	files = append(files, unit)
	return append(files, dropIns...)
}

// Property reads one property off a unit through `systemctl show`, trimmed.
// false where systemd is not running or the ask failed.
func Property(unit, property string) (string, bool) {
	if !Running() {
		return "", false
	}
	out, err := runcmd.OutputWithin(30*time.Second, "systemctl", "show", unit, "-p", property, "--value")
	if err != nil {
		return "", false
	}
	return strings.TrimSpace(out), true
}

// Int is unitProperty for the numeric ones. "infinity" is systemd saying
// there is no limit, which parses as neither a number nor an error worth
// reporting: it is a bound nobody set.
func Int(unit, property string) (int64, bool) {
	out, ok := Property(unit, property)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseInt(out, 10, 64)
	return value, err == nil
}

// InstalledAccounts is faramir's three service accounts at the names this host
// uses, read off the installed units the way `doctor` and the rule renderer
// read them, and the standard name where a unit cannot be read.
//
// Exported for the caller that has to refuse them as answers to "which account
// is the operator". A compiled-in list is right about a default install and
// silently wrong about a renamed one, and being wrong there means recording a
// service account as the operator and rendering every path rule against its
// home.
//
// No config directory: these come from the units, whose paths this package
// already knows, and a host that renamed an account renamed it there.
func InstalledAccounts() []string {
	broker, _ := User(BrokerUnit)
	keeper, _ := User(KeeperUnit)
	exec, _ := User(ExecUnit)
	return []string{
		cmp.Or(broker, hostlayout.DefaultBrokerUser),
		cmp.Or(keeper, hostlayout.DefaultKeeperUser),
		cmp.Or(exec, hostlayout.DefaultExecUser),
	}
}
