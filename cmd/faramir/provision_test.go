package main

import (
	"encoding/json"
	"net"
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/install"
	"github.com/andornaut/faramir/internal/sockutil"
)

// statusBroker answers the status op with the given config list, the body being
// JSON carried as a string in output.
func statusBroker(t *testing.T, configs []string) string {
	t.Helper()
	socketPath := filepath.Join(t.TempDir(), "b.sock")
	listener, err := net.Listen("unix", socketPath)
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
