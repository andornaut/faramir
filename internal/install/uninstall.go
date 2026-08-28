package install

import (
	"fmt"
	"os"
	"path/filepath"
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
		logrotateConfig,
		sudoersFile,
		pamServiceFile,
		DefaultRunDir,
	}
}

// uninstallDirs is what this install rendered or copied for its own use, removed
// whole. Everything in them is faramir's own: the hook's deny list, the wrapper
// it sources, the PAM helper, the environment file the grant named, and the
// documentation written out beside them.
func uninstallDirs() []string {
	return []string{DefaultLibexecDir, DefaultDocDir}
}

// Uninstall removes the broker and returns what it left behind: the accounts,
// the config, the secrets directory and the audit log. Deleting the age key
// would make every managed sops file unreadable, retroactively.
func Uninstall(configDir string) ([]string, error) {
	if configDir == "" {
		configDir = DefaultConfigDir
	}
	// What this run could not take back out, reported with everything else it
	// leaves. Appended to rather than returned early: an uninstall that stopped
	// here would leave a host with its units gone and no daemon-reload.
	var leftBehind []string
	if systemdRunning() {
		run := &runner{}
		units := append(append([]string{"disable", "--now"}, sockets...), services...)
		// Not fatal: a unit already gone is the state this is reaching for.
		_, _ = run.command("systemctl", units...)
	}
	for _, name := range unitNames() {
		if err := os.Remove(filepath.Join(systemUnitDir, name)); err != nil &&
			!os.IsNotExist(err) {
			return nil, err
		}
	}
	for _, unit := range []string{"faramir-broker", "faramir-keeper", "faramir-exec"} {
		if err := os.RemoveAll(filepath.Join(systemUnitDir, unit+".service.d")); err != nil {
			return nil, err
		}
	}
	for _, path := range uninstallPaths() {
		if err := os.RemoveAll(path); err != nil {
			return nil, err
		}
	}
	// The block a sudo-rs host's grant put in the stacks every account's sudo
	// reads. Not a file to remove: everything around them is the distribution's,
	// so this is a splice, and it runs whatever the host's sudo is now -- an
	// install that wrote the block and an operator who has since switched the
	// `sudo` alternatives group would otherwise keep a branch pointing at a
	// service this uninstall just deleted.
	// Reported rather than fatal: by this point the units and the files are gone,
	// so failing here would leave a half-uninstalled host and no daemon-reload.
	// The one case that fails is a stack carrying one marker without the other,
	// which is an edit somebody made and which this must not guess at.
	if _, err := removeSudoPamBlock(fsys{}); err != nil {
		leftBehind = append(leftBehind, "the faramir block in a shared PAM stack: "+
			err.Error())
	}
	if systemdRunning() {
		run := &runner{}
		if _, err := run.command("systemctl", "daemon-reload"); err != nil {
			return nil, err
		}
	}
	for _, name := range installedBinaries {
		if err := os.Remove(filepath.Join(DefaultBinDir, name)); err != nil && !os.IsNotExist(err) {
			return nil, err
		}
	}
	for _, dir := range uninstallDirs() {
		if err := os.RemoveAll(dir); err != nil {
			return nil, err
		}
	}
	return append(leftBehind,
		filepath.Join(configDir, "age.key")+
			" -- deleting it makes every managed sops file unreadable",
		filepath.Join(configDir, "secrets")+"/ -- the managed sops files",
		filepath.Join(configDir, "config.toml")+" -- the base config",
		DefaultLogDir+"/ -- the audit log",
		fmt.Sprintf("users %s, %s and %s, and the shared group. %s's own password "+
			"is not cleared: `usermod -L %s`",
			DefaultBrokerUser, DefaultKeeperUser, DefaultExecUser,
			DefaultExecUser, DefaultExecUser),
		"a shared tree's group and setgid bits, and the traversal granted to reach it",
		"an enrolled tree's own agent configuration: for Claude Code, the settings "+
			"naming the hook that routes what it runs",
		"each agent's account-wide configuration in the agent account's home: the deny "+
			"rules, and the credentials section between "+sectionBegin+" and "+
			sectionEnd+" in the file that agent reads for every project. Both are "+
			"in files the operator owns and edits, so removing the section is "+
			"deleting those lines",
	), nil
}
