package install

import (
	"fmt"
	"os"
	"path/filepath"
)

// Uninstall removes the broker and returns what it deliberately left behind.
//
// It leaves the accounts, the config, the store and the audit log alone.
// Deleting the age key would make every managed sops file unreadable,
// retroactively, and that is not a decision a teardown should make for you.
func Uninstall(configDir string) ([]string, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	if systemdRunning() {
		run := &runner{}
		units := append(append([]string{"disable", "--now"}, sockets...), services...)
		// Not fatal: a unit that is already gone, or a system where one never
		// started, is exactly the state this is trying to reach.
		_, _ = run.command("systemctl", units...)
	}
	for _, name := range unitNames() {
		if err := os.Remove(filepath.Join("/etc/systemd/system", name)); err != nil &&
			!os.IsNotExist(err) {
			return nil, err
		}
	}
	for _, unit := range []string{"faramir-broker", "faramir-keeper", "faramir-exec"} {
		if err := os.RemoveAll(filepath.Join("/etc/systemd/system", unit+".service.d")); err != nil {
			return nil, err
		}
	}
	// The sockets went with the units above, so the runtime directory holds
	// nothing.
	for _, path := range []string{"/etc/tmpfiles.d/faramir.conf", DefaultRunDir} {
		if err := os.RemoveAll(path); err != nil {
			return nil, err
		}
	}
	if systemdRunning() {
		run := &runner{}
		if _, err := run.command("systemctl", "daemon-reload"); err != nil {
			return nil, err
		}
	}
	for _, name := range append(append([]string{}, installedBinaries...), legacyBinaries...) {
		if err := os.Remove(filepath.Join(DefaultBinDir, name)); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	for _, dir := range []string{DefaultLibexecDir, DefaultDocDir} {
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
	}
	return []string{
		filepath.Join(DefaultConfigDir, "age.key") +
			" -- deleting it makes every managed sops file unreadable",
		filepath.Join(configDir, "secrets") + "/ -- the managed sops files",
		filepath.Join(configDir, "config.toml") + " -- the base config",
		filepath.Join(configDir, "config.d") + "/ -- per-consumer settings merged over it",
		DefaultLogDir + "/ -- the audit log",
		fmt.Sprintf("users %s, %s and %s, and the shared group",
			DefaultBrokerUser, DefaultKeeperUser, DefaultExecUser),
		"a shared tree's group and setgid bits, and the traversal granted to reach it",
		"a project's .claude/settings.json naming the hook, and its .mcp.json",
	}, nil
}
