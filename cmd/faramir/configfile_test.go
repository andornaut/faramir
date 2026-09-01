package main

import (
	"os"
	"path/filepath"
	"testing"
)

// The variable wins over a running broker, which is what makes it the way out
// for a host whose install the broker cannot be asked about.
func TestAnEnvironmentConfigWins(t *testing.T) {
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	got, err := findConfigFile(status{configDir: "/etc/faramir"})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != "/from/env/config.toml" {
		t.Errorf("findConfigFile = %q, want the path the variable names", got)
	}
}

// It names the config file. A directory is refused rather than read as one, or
// FARAMIR_CONFIG=/etc/faramir would make the install /etc.
func TestAnEnvironmentConfigNamingADirectoryIsRefused(t *testing.T) {
	t.Setenv("FARAMIR_CONFIG", t.TempDir())
	if got, err := findConfigFile(status{}); err == nil {
		t.Errorf("a directory resolved to %q instead of being refused", got)
	}
}

// The path an edit under sudo takes on an install whose config moved out of the
// compiled default.
func TestTheBrokerUnitNamesTheLiveConfig(t *testing.T) {
	want := "/home/op/" + ".config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	got, err := findConfigFile(askBroker(socketDefault()))
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != want {
		t.Errorf("findConfigFile = %q, want the path the unit names", got)
	}
}

// A unit naming no config is a host nothing can be asked about: no broker
// answering and no unit naming a file is not the compiled-in default, it is an
// install this command cannot find.
func TestAUnitWithoutTheVariableIsAnError(t *testing.T) {
	withUnit(t, "[Service]\nUser=faramir-broker\n")
	if got, err := findConfigFile(askBroker(socketDefault())); err == nil {
		t.Errorf("findConfigFile invented %q from a unit that names no config", got)
	}
}

// A daemon run from a shell finds the install rather than the compiled-in
// default, which is what `faramir broker --check` needs on an install that
// moved. Under systemd the unit sets FARAMIR_CONFIG and none of this is
// reached; sudo clears it, which is how the check is run.
func TestADaemonTakesTheConfigTheUnitNames(t *testing.T) {
	want := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+want+"\n")
	got, err := findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != want {
		t.Errorf("the daemon ladder = %q, want the path the unit names", got)
	}
	t.Setenv("FARAMIR_CONFIG", "/from/env/config.toml")
	got, err = findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != "/from/env/config.toml" {
		t.Errorf("the daemon ladder = %q, want the path the variable names", got)
	}
}

// The daemons must not ask the broker which config to load: each is a process
// that may be about to bind that socket, and connecting to it would activate
// the installed daemon and leave the two contending for the path. A client
// command asks and takes the answer, which is what makes this observable.
func TestADaemonDoesNotAskTheBroker(t *testing.T) {
	live := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(live, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	unit := "/home/op/.config/faramir/config.toml"
	withUnit(t, "[Service]\nUser=faramir-broker\nEnvironment=FARAMIR_CONFIG="+unit+"\n")
	t.Setenv("FARAMIR_SOCKET", statusBroker(t, live))

	got, err := findConfigFile(askBroker(socketDefault()))
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != live {
		t.Errorf("the client ladder = %q, want the running broker's own answer %q", got, live)
	}
	got, err = findConfigFile(status{})
	if err != nil {
		t.Fatalf("findConfigFile: %v", err)
	}
	if got != unit {
		t.Errorf("the daemon ladder = %q, want the unit's %q: a daemon asked the "+
			"socket it may be about to bind", got, unit)
	}
}

// withUnit points the fallback at a fixture and restores it afterwards.
func withUnit(t *testing.T, body string) {
	t.Helper()
	unit := filepath.Join(t.TempDir(), "faramir-broker.service")
	if err := os.WriteFile(unit, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	original := brokerUnit
	brokerUnit = unit
	t.Cleanup(func() { brokerUnit = original })
	t.Setenv("FARAMIR_CONFIG", "")
	// A socket nothing is listening on, so the unit is what is left and a live
	// install on the host cannot decide this.
	t.Setenv("FARAMIR_SOCKET", filepath.Join(t.TempDir(), "absent.sock"))
}
