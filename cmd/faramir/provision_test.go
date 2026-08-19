package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// statusBroker answers the status op with the given config list, the body being
// JSON carried as a string in output.
func statusBroker(t *testing.T, configs []string) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	body, err := json.Marshal(map[string]any{"configs": configs})
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := sockutil.ReadLine(conn, 1<<20); err != nil {
					return
				}
				_ = sockutil.Send(conn, map[string]any{
					"exit_code": 0, "output": string(body),
				})
			}()
		}
	}()
	return socketPath
}

// The compiled-in default is only right for a host that took it, so the broker
// is asked instead.
func TestResolveConfigDirAsksTheBroker(t *testing.T) {
	socket := statusBroker(t, []string{
		"/home/op/.config/faramir/config.toml",
		"/home/op/.config/faramir/config.d/a.toml",
	})
	if got := resolveConfigDir("", socket); got != "/home/op/.config/faramir" {
		t.Errorf("resolveConfigDir = %q, want /home/op/.config/faramir", got)
	}
}

// An operator who names one is examining that install, whatever a broker
// says.
func TestResolveConfigDirPrefersTheFlag(t *testing.T) {
	socket := statusBroker(t, []string{"/home/op/.config/faramir/config.toml"})
	if got := resolveConfigDir("/etc/elsewhere", socket); got != "/etc/elsewhere" {
		t.Errorf("resolveConfigDir = %q, want the flag to win", got)
	}
}

// pointBrokerUnit aims the unit step of the ladder at a fixture, so a test
// about a later step is not answered by this host's own install.
func pointBrokerUnit(t *testing.T, body string) {
	t.Helper()
	unit := filepath.Join(t.TempDir(), "faramir-broker.service")
	if body != "" {
		if err := os.WriteFile(unit, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	original := brokerUnit
	brokerUnit = unit
	t.Cleanup(func() { brokerUnit = original })
}

// The step between a silent broker and the default: a broker that is not
// running was still installed to load something, and its unit says what.
func TestResolveConfigDirReadsTheUnitWhenTheBrokerIsSilent(t *testing.T) {
	pointBrokerUnit(t, "[Service]\nUser=faramir-broker\n"+
		"Environment=FARAMIR_CONFIG=/home/op/.config/faramir/config.toml\n")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if got := resolveConfigDir("", missing); got != "/home/op/.config/faramir" {
		t.Errorf("resolveConfigDir = %q, want the directory the unit names", got)
	}
}

// Nothing listening and no unit is a host with no install, which is the case
// doctor exists for, so it carries on against the default.
func TestResolveConfigDirFallsBackWhenTheBrokerIsSilent(t *testing.T) {
	pointBrokerUnit(t, "")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if got := resolveConfigDir("", missing); got != install.DefaultConfigDir {
		t.Errorf("resolveConfigDir = %q, want %q", got, install.DefaultConfigDir)
	}
}

// A broker that answers with something else is the same as one that does not.
func TestResolveConfigDirFallsBackOnAnEmptyConfigList(t *testing.T) {
	pointBrokerUnit(t, "")
	socket := statusBroker(t, []string{})
	if got := resolveConfigDir("", socket); got != install.DefaultConfigDir {
		t.Errorf("resolveConfigDir = %q, want %q", got, install.DefaultConfigDir)
	}
}

// The unit and its drop-ins, in the order systemd reads them. init refuses a
// config move against the same reader, so a resolver that stopped at the main
// unit would hand init a directory init then refuses as a move: the operator
// passed no --config-dir, and the only way past would be --move-config, which
// moves the daemons the other way.
func TestTheUnitReaderTakesTheDropInTheDaemonsLoad(t *testing.T) {
	pointBrokerUnit(t, "[Service]\nUser=faramir-broker\n"+
		"Environment=FARAMIR_CONFIG=/etc/faramir/config.toml\n")
	if err := os.Mkdir(brokerUnit+".d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(brokerUnit+".d", "10-moved.conf"),
		[]byte("[Service]\nEnvironment=FARAMIR_CONFIG=/srv/faramir/config.toml\n"),
		0o644); err != nil {
		t.Fatal(err)
	}

	if got := unitConfigFile(); got != "/srv/faramir/config.toml" {
		t.Errorf("unitConfigFile = %q, want the drop-in's path", got)
	}
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if got := resolveConfigDir("", missing); got != "/srv/faramir" {
		t.Errorf("resolveConfigDir = %q, want the directory the daemons load", got)
	}
}

// refusingBroker answers every request the way a daemon of another release
// does: the op is never read, so there is no body, and the response names the
// build that answered, which here is this one.
func refusingBroker(t *testing.T) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer func() { _ = conn.Close() }()
				if _, err := sockutil.ReadLine(conn, 1<<20); err != nil {
					return
				}
				_ = sockutil.Send(conn, protocol.ErrorResponse(
					"bad_request", version.Mismatch("0.0.1"), ""))
			}()
		}
	}()
	return socketPath
}

// Skew is the one state where the broker refuses the very question that would
// report it, the version being checked before the op is read. The refusal names
// the build that answered, so it is the answer: taken any other way, `doctor`
// reports a broker that said nothing, which is a warning naming no build and is
// what a stopped install looks like.
func TestAskBrokerTakesTheVersionFromARefusal(t *testing.T) {
	// The fixture answers as this build, which is what a running broker of
	// another release is to the binary asking.
	got := askBroker(refusingBroker(t))
	if got.version != version.Version {
		t.Errorf("askBroker version = %q, want %q from the refusal",
			got.version, version.Version)
	}
	// There is no status body in a refusal, so nothing may be claimed about
	// where that broker's config sits: discoverConfigFile reads the unit.
	if got.configDir != "" {
		t.Errorf("askBroker configDir = %q, want empty: a refusal carries no body",
			got.configDir)
	}
}
