package install

import (
	"fmt"
	"os"
	"path/filepath"
)

// Uninstall removes the broker and returns what it left behind: the accounts,
// the config, the secrets directory and the audit log.  Deleting the age key
// would make every managed sops file unreadable, retroactively.
func Uninstall(configDir string) ([]string, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	if systemdRunning() {
		run := &runner{}
		units := append(append([]string{"disable", "--now"}, sockets...), services...)
		// Not fatal: a unit already gone is the state this is reaching for.
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
	// The sockets went with the units above.
	for _, path := range []string{"/etc/tmpfiles.d/faramir.conf", logrotateConfig, DefaultRunDir} {
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
		"each enrolled agent's configuration in a project: the settings naming the " +
			"hook, the plugin that calls it, and the MCP registration",
	}, nil
}
