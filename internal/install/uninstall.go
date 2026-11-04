package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/hostunit"
)

// uninstallPaths is what is removed before the daemons are reloaded, each with
// os.RemoveAll.
//
// The sockets went with the units. The sudoers grant goes with them: it names
// the executor's uid, and with the broker gone nothing is left to answer what it
// asks, so keeping it would leave a grant behind with no arrangement around it.
// The PAM service the grant names goes too, or the host keeps a service that
// execs a helper this uninstall deleted. The environment file the grant names
// goes with uninstallDirs below, being one of the files this install renders into
// its own libexec directory.
//
// Nothing here or there may name the config directory or one above it: removing
// it would take the age key and the managed sops files with it, which is the one
// thing an uninstall must not do. TestUninstallLeavesTheConfigDirectory holds
// that.
func uninstallPaths() []string {
	return []string{
		"/etc/tmpfiles.d/faramir.conf",
		hostlayout.LogrotateConfig,
		hostlayout.SudoersFile,
		hostlayout.PamServiceFile,
		hostlayout.DefaultRunDir,
	}
}

// uninstallDirs is what this install rendered or copied for its own use, removed
// whole. Everything in them is faramir's own: the hook's deny list, the wrapper
// it sources, the PAM helper, the environment file the grant named, and the
// documentation written out beside them.
func uninstallDirs() []string {
	return []string{hostlayout.DefaultLibexecDir, hostlayout.DefaultDocDir}
}

// Uninstall removes the broker and returns what it left behind: the accounts,
// the config, the secrets directory and the audit log. Deleting the age key
// would make every managed sops file unreadable, retroactively.
func Uninstall(configDir string) ([]string, error) {
	return uninstall(uninstallOps{
		remove: os.Remove, removeAll: os.RemoveAll,
		removeBlock: func() error {
			_, err := hostsudo.RemoveBlock(hostfs.FS{})
			return err
		},
	}, configDir)
}

type uninstallOps struct {
	remove      func(string) error
	removeAll   func(string) error
	removeBlock func() error
}

func uninstall(ops uninstallOps, configDir string) ([]string, error) {
	if configDir == "" {
		configDir = hostlayout.DefaultConfigDir
	}
	// The accounts and group this install runs as, read before the units that
	// name them are removed: an adopted account need not have the default name,
	// and the list below tells the operator what to delete.
	accounts := installedAccounts(configDir)
	var failures []error
	if hostunit.Running() {
		for _, unit := range append(slices.Clone(hostunit.Sockets), hostunit.Services...) {
			// One unit at a time, so a unit file already gone, which is the state a
			// re-run after a partial uninstall is in, cannot keep the others from
			// being stopped. Verify the result even when disabling failed.
			_, stopErr := command("systemctl", "disable", "--now", unit)
			state, known := hostunit.State(unit)
			_, fileErr := os.Stat(hostunit.Path(unit))
			// Disabling an absent unit fails on an idempotent re-run. Only a
			// verified inactive unit makes that failure harmless.
			if stopErr != nil && (!known || state != "inactive" || !os.IsNotExist(fileErr)) {
				failures = append(failures, failed(unit+" not stopped", stopErr))
			}
			switch {
			case !known:
				failures = append(failures, fmt.Errorf("%s: could not verify that the unit stopped", unit))
			case state != "inactive" && state != "failed":
				failures = append(failures, fmt.Errorf("%s: state %q after stop\n  run systemctl stop %s", unit, state, unit))
			}
		}
	}
	for _, name := range agentcfg.UnitNames() {
		if err := ops.remove(filepath.Join(hostunit.SystemUnitDir, name)); err != nil &&
			!os.IsNotExist(err) {
			failures = append(failures, err)
		}
	}
	for _, unit := range hostunit.Services {
		if err := ops.removeAll(filepath.Join(hostunit.SystemUnitDir, unit+".d")); err != nil {
			failures = append(failures, err)
		}
	}
	for _, path := range uninstallPaths() {
		if err := ops.removeAll(path); err != nil {
			failures = append(failures, err)
		}
	}
	// The block a sudo-rs host's grant put in the stacks every account's sudo
	// reads. Not a file to remove: everything around them is the distribution's,
	// so this is a splice, and it runs whatever the host's sudo is now -- an
	// install that wrote the block and an operator who has since switched the
	// `sudo` alternatives group would otherwise keep a branch pointing at a
	// service this uninstall just deleted.
	// Accumulate the error so daemon-reload and independent cleanup still run.
	// The one case that fails is a stack carrying one marker without the other,
	// which is an edit somebody made and which this must not guess at.
	if err := ops.removeBlock(); err != nil {
		failures = append(failures, fmt.Errorf("faramir block not removed from a shared PAM stack: %w", err))
	}
	if hostunit.Running() {
		if _, err := command("systemctl", "daemon-reload"); err != nil {
			failures = append(failures, failed("systemctl daemon-reload", err))
		}
	}
	for _, name := range installedBinaries {
		if err := ops.remove(filepath.Join(hostlayout.DefaultBinDir, name)); err != nil && !os.IsNotExist(err) {
			failures = append(failures, err)
		}
	}
	for _, dir := range uninstallDirs() {
		if err := ops.removeAll(dir); err != nil {
			failures = append(failures, err)
		}
	}
	return []string{
		filepath.Join(configDir, "age.key") + " (the only key to the managed files)",
		filepath.Join(configDir, "secrets") + "/",
		config.FileIn(configDir),
		hostlayout.DefaultLogDir + "/ (the audit log)",
		fmt.Sprintf("users %s, %s and %s, group %s (lock %s: `usermod -L %s`)",
			accounts.broker, accounts.keeper, accounts.exec, accounts.client,
			accounts.exec, accounts.exec),
		"each shared tree's group, setgid bits and traversal grants",
		"each enrolled tree's agent configuration",
		"each agent's account-wide configuration: deny rules, and the section between " +
			agentcfg.SectionBegin + " and " + agentcfg.SectionEnd + " (remove by hand)",
	}, errors.Join(failures...)
}

// serviceAccounts is the names an install runs as.
type serviceAccounts struct{ broker, keeper, exec, client string }

// installedAccounts reads the accounts off the units' own User= and the client
// group off the config, as init adopts them, each falling back to the default
// where the install does not say.
func installedAccounts(configDir string) serviceAccounts {
	named := func(unit, fallback string) string {
		if account, err := hostunit.User(unit); err == nil && account != "" {
			return account
		}
		return fallback
	}
	accounts := serviceAccounts{
		broker: named(hostunit.BrokerUnit, hostlayout.DefaultBrokerUser),
		keeper: named(hostunit.KeeperUnit, hostlayout.DefaultKeeperUser),
		exec:   named(hostunit.ExecUnit, hostlayout.DefaultExecUser),
		client: hostlayout.DefaultClientGroup,
	}
	if cfg, err := config.Load(config.FileIn(configDir)); err == nil &&
		cfg.Server.AllowedGroup != "" {
		accounts.client = cfg.Server.AllowedGroup
	}
	return accounts
}
