package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/enrol"
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

// UninstallReport is what an uninstall took faramir out of before removing the
// install, what it could not clean, and what it left behind on purpose.
type UninstallReport struct {
	Unenrolled []string
	Warnings   []string
	Kept       []string
}

// Uninstall removes the broker and reports what it left behind: the accounts,
// the config, the secrets directory and the audit log. Deleting the age key
// would make every managed sops file unreadable, retroactively.
func Uninstall(configDir string) (UninstallReport, error) {
	return uninstall(uninstallOps{
		remove: os.Remove, removeAll: os.RemoveAll,
		removeBlock: func() error {
			_, err := hostsudo.RemoveBlock(hostfs.FS{})
			return err
		},
		unenrol: enrol.Unenrol,
		unenrolHome: func(account string) (enrol.UnenrolReport, error) {
			uid, err := hostfs.LookupUser(account)
			if err != nil {
				return enrol.UnenrolReport{}, err
			}
			home, err := homeDir(account)
			if err != nil {
				return enrol.UnenrolReport{}, err
			}
			return enrol.UnenrolHome(uid, home)
		},
	}, configDir)
}

type uninstallOps struct {
	remove      func(string) error
	removeAll   func(string) error
	removeBlock func() error
	unenrol     func(enrol.UnenrolOptions) (enrol.UnenrolReport, error)
	unenrolHome func(account string) (enrol.UnenrolReport, error)
}

func uninstall(ops uninstallOps, configDir string) (UninstallReport, error) {
	if configDir == "" {
		configDir = hostlayout.DefaultConfigDir
	}
	// The accounts and group this install runs as, read before the units that
	// name them are removed: an adopted account need not have the default name,
	// and the list below tells the operator what to delete.
	accounts := installedAccounts(configDir)
	var report UninstallReport
	unenrolAgents(ops, &report, configDir, accounts.agent)
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
	report.Kept = []string{
		filepath.Join(configDir, "age.key") + " (the only key to the managed files)",
		filepath.Join(configDir, "secrets") + "/",
		config.FileIn(configDir),
		hostlayout.DefaultLogDir + "/ (the audit log)",
		fmt.Sprintf("users %s, %s and %s, group %s (lock %s: `usermod -L %s`)",
			accounts.broker, accounts.keeper, accounts.exec, accounts.client,
			accounts.exec, accounts.exec),
		"each shared tree's group, setgid bits and traversal grants",
		"each enrolled tree's permission rules, and each agent's account-wide deny rules",
		`the Antigravity hook under "faramir" in ~/.gemini/config/hooks.json (remove by hand)`,
	}
	return report, errors.Join(failures...)
}

// unenrolAgents takes faramir out of every enrolled tree and the agent
// account's home, before anything else is removed. A hook or plugin left
// behind execs the binary this uninstall deletes, and the plugins fail closed:
// every shell command in every project would be refused. A tree or home that
// cannot be cleaned is a warning naming it rather than a reason to keep the
// broker.
//
// A missing tree keeps its record, which is in the config directory an
// uninstall keeps: storage that is not mounted is not a tree to forget.
func unenrolAgents(ops uninstallOps, report *UninstallReport, configDir, agent string) {
	warnf := func(format string, args ...any) {
		report.Warnings = append(report.Warnings, fmt.Sprintf(format, args...))
	}
	trees, err := agentcfg.ReadEnrolledWhy(configDir)
	if err != nil {
		warnf("enrolled trees not unenrolled: %v\n  remove their agent configuration by hand", err)
	}
	for _, tree := range trees {
		if !hostfs.Exists(tree.Dir) {
			warnf("enrolled tree %s not unenrolled: no directory there\n"+
				"  remove its agent configuration by hand if it comes back", tree.Dir)
			continue
		}
		result, err := ops.unenrol(enrol.UnenrolOptions{
			Dir: tree.Dir, AgentUser: tree.AgentUser, ConfigDir: configDir,
		})
		if err != nil {
			warnf("enrolled tree %s not unenrolled: %v", tree.Dir, err)
			continue
		}
		report.Warnings = append(report.Warnings, result.Warnings...)
		report.Unenrolled = append(report.Unenrolled, result.Dir)
	}
	if agent == "" {
		warnf("account-wide agent configuration not removed: no agent account in %s", config.FileIn(configDir))
		return
	}
	result, err := ops.unenrolHome(agent)
	if err != nil {
		warnf("account-wide agent configuration of %s not removed: %v", agent, err)
		return
	}
	report.Unenrolled = append(report.Unenrolled, result.Dir+" (account-wide)")
}

// serviceAccounts is the names an install runs as, and the agent account it
// was installed for.
type serviceAccounts struct{ broker, keeper, exec, client, agent string }

// installedAccounts reads the accounts off the units' own User= and the client
// group and agent account off the config, as init adopts them, each service
// name falling back to the default where the install does not say. The agent
// account has no default.
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
	if cfg, err := config.Load(config.FileIn(configDir)); err == nil {
		if cfg.Server.AllowedGroup != "" {
			accounts.client = cfg.Server.AllowedGroup
		}
		accounts.agent = cfg.Server.AgentUser
	}
	return accounts
}
