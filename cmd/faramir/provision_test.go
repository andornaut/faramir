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

// statusBroker answers the status op with the given config list, wrapped the way
// the broker wraps it: the body is JSON carried as a string in output.
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

// The compiled-in default is only right for a host that took it. Anywhere else
// doctor would report a working install as broken, so it asks the broker, which
// is the one thing that knows where the config is without being told.
func TestResolveConfigDirAsksTheBroker(t *testing.T) {
	socket := statusBroker(t, []string{
		"/home/op/.faramir/config.toml",
		"/home/op/.faramir/config.d/a.toml",
	})
	if got := resolveConfigDir("", socket); got != "/home/op/.faramir" {
		t.Errorf("resolveConfigDir = %q, want /home/op/.faramir", got)
	}
}

// An operator who names one is examining that install, whatever a broker says,
// including the case where they are asking about a host whose broker is the
// thing that is wrong.
func TestResolveConfigDirPrefersTheFlag(t *testing.T) {
	socket := statusBroker(t, []string{"/home/op/.faramir/config.toml"})
	if got := resolveConfigDir("/etc/elsewhere", socket); got != "/etc/elsewhere" {
		t.Errorf("resolveConfigDir = %q, want the flag to win", got)
	}
}

// Nothing listening is the case doctor exists for, so it has to carry on rather
// than fail: the default is the only place left to look, and a broker that does
// not answer is itself a finding.
func TestResolveConfigDirFallsBackWhenTheBrokerIsSilent(t *testing.T) {
	missing := filepath.Join(t.TempDir(), "absent.sock")
	if got := resolveConfigDir("", missing); got != install.DefaultConfigDir {
		t.Errorf("resolveConfigDir = %q, want %q", got, install.DefaultConfigDir)
	}
}

// A broker that answers with something else is the same as one that does not.
func TestResolveConfigDirFallsBackOnAnEmptyConfigList(t *testing.T) {
	socket := statusBroker(t, []string{})
	if got := resolveConfigDir("", socket); got != install.DefaultConfigDir {
		t.Errorf("resolveConfigDir = %q, want %q", got, install.DefaultConfigDir)
	}
}
