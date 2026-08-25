package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/protocol"
	"github.com/andornaut/faramir/internal/sockutil"
	"github.com/andornaut/faramir/internal/version"
)

// statusBroker answers the status op naming the given config file, the body
// being JSON carried as a string in output.
func statusBroker(t *testing.T, configFile string) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := (&net.ListenConfig{}).Listen(t.Context(), "unix", socketPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close(); _ = os.Remove(socketPath) })

	body, err := json.Marshal(map[string]any{"config": configFile})
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
	socket := statusBroker(t, "/home/op/.config/faramir/config.toml")
	t.Setenv("FARAMIR_CONFIG", "")
	got, err := resolveConfigDir(socket)
	if err != nil {
		t.Fatalf("resolveConfigDir: %v", err)
	}
	if got != "/home/op/.config/faramir" {
		t.Errorf("resolveConfigDir = %q, want /home/op/.config/faramir", got)
	}
}

// The way out for a host whose broker is down and whose unit is gone. No
// command takes a directory, so this is the only thing an operator can say,
// and it is the same variable the units give the daemons.
func TestResolveConfigDirPrefersTheEnvironment(t *testing.T) {
	socket := statusBroker(t, "/home/op/.config/faramir/config.toml")
	t.Setenv("FARAMIR_CONFIG", "/etc/elsewhere/config.toml")
	got, err := resolveConfigDir(socket)
	if err != nil {
		t.Fatalf("resolveConfigDir: %v", err)
	}
	if got != "/etc/elsewhere" {
		t.Errorf("resolveConfigDir = %q, want the environment to win", got)
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
	t.Setenv("FARAMIR_CONFIG", "")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	got, err := resolveConfigDir(missing)
	if err != nil {
		t.Fatalf("resolveConfigDir: %v", err)
	}
	if got != "/home/op/.config/faramir" {
		t.Errorf("resolveConfigDir = %q, want the directory the unit names", got)
	}
}

// Nothing listening and no unit is a host with no install. The compiled-in
// default is not the answer: it is a guess, and a command that acted on it
// would report on, or delete, a directory that is not this host's install.
func TestResolveConfigDirFailsWhenNothingAnswers(t *testing.T) {
	pointBrokerUnit(t, "")
	t.Setenv("FARAMIR_CONFIG", "")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if _, err := resolveConfigDir(missing); err == nil {
		t.Error("a host with no broker, no unit and no environment resolved a " +
			"directory; nothing knows which install that would be")
	}
}

// A broker that answers with something else is the same as one that does not.
func TestResolveConfigDirFailsWhenTheBrokerNamesNoConfig(t *testing.T) {
	pointBrokerUnit(t, "")
	t.Setenv("FARAMIR_CONFIG", "")
	socket := statusBroker(t, "")
	if _, err := resolveConfigDir(socket); err == nil {
		t.Error("a status naming no config resolved a directory")
	}
}

// init is the exception: a host with no install has no broker to ask and no
// unit to read, which is the case init is for.
func TestInitConfigDirFallsBackToTheDefault(t *testing.T) {
	pointBrokerUnit(t, "")
	t.Setenv("FARAMIR_CONFIG", "")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if got := initConfigDir("", missing); got != install.DefaultConfigDir {
		t.Errorf("initConfigDir = %q, want %q", got, install.DefaultConfigDir)
	}
	if got := initConfigDir("/etc/elsewhere", missing); got != "/etc/elsewhere" {
		t.Errorf("initConfigDir = %q, want the flag to win", got)
	}
}

// The unit and its drop-ins, in the order systemd reads them. init refuses a
// config move against the same reader, so a resolver that stopped at the main
// unit would hand init a directory init then refuses as a move: the operator
// passed no --config-dir, and the only way past would be --repoint-config, which
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
	t.Setenv("FARAMIR_CONFIG", "")
	missing := filepath.Join(t.TempDir(), "absent.sock")
	got, err := resolveConfigDir(missing)
	if err != nil {
		t.Fatalf("resolveConfigDir: %v", err)
	}
	if got != "/srv/faramir" {
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
	// where that broker's config sits: configFileFrom reads the unit instead.
	if got.configDir != "" {
		t.Errorf("askBroker configDir = %q, want empty: a refusal carries no body",
			got.configDir)
	}
}

// The flag was called --move-config, which read as though init relocated the
// directory. It does not: the daemons are pointed at the new one and the old
// stays where it is. The old spelling keeps working, a fleet's converge being
// where this is typed, and is hidden from --help so nothing learns it now.
func TestTheRenamedRepointFlagStillTakesItsOldSpelling(t *testing.T) {
	for _, spelling := range []string{"--repoint-config", "--move-config"} {
		c := newInitCmd()
		if err := c.Flags().Parse([]string{spelling}); err != nil {
			t.Fatalf("%s: %v", spelling, err)
		}
		on, err := c.Flags().GetBool(strings.TrimPrefix(spelling, "--"))
		if err != nil || !on {
			t.Errorf("%s did not set: %v", spelling, err)
		}
	}
	c := newInitCmd()
	if flag := c.Flags().Lookup("move-config"); flag == nil || !flag.Hidden {
		t.Error("the old spelling is still offered in --help")
	}
	if c.Flags().Lookup("repoint-config") == nil {
		t.Fatal("--repoint-config is not registered")
	}
}
