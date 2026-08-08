package install

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/sharetree"
)

// installedBinaries go to BinDir.  faramir-guard is not among them: it is the
// PreToolUse hook and installs next to its deny list under LibexecDir.
var installedBinaries = []string{
	"faramir", "faramir-broker", "faramir-keeper", "faramir-exec", "faramir-mcp",
}

// guardSource is where faramir-guard is read from.  It installs under
// LibexecDir rather than beside the others in BinDir, so a faramir that is
// re-installing itself from BinDir finds every sibling except this one, and
// the preflight refused the whole run over it.
//
// The already-installed copy is the fallback, and it is the honest source in
// that case: re-installing from BinDir re-installs the versions that are
// already there, and the hook is one of them.  Empty when neither exists, which
// preflight reports as missing rather than failing at the copy, after the
// accounts and the age key have been created.
func (r *runner) guardSource() string {
	beside := filepath.Join(r.opts.Binaries, "faramir-guard")
	if exists(beside) {
		return beside
	}
	if installed := filepath.Join(r.layout.LibexecDir, "faramir-guard"); exists(installed) {
		return installed
	}
	return ""
}

// stepDirectories creates what everything below writes into.
func (r *runner) stepDirectories() error {
	changed := false

	// 0755 root:root, including inside an operator's own home.  The broker, the
	// keeper and the agent all read the config from here, so the directory
	// cannot belong to any one of them, and this one is not a matter of taste:
	// config.d/*.toml merges over config.toml, [exec.base_env] merges key by
	// key, and PATH there is the only PATH a brokered command's child gets.
	// Whoever can write a drop-in chooses what the executor runs when a command
	// names a bare program, and it runs with the requested secret in its
	// environment.  An agent runs as the operator, so leaving these writable by
	// the operator hands that choice to the agent.
	//
	// own=true, unlike before: a directory that is already operator-owned is one
	// this has to take back, which is the whole point.  Editing config by hand
	// needs sudo now, the same as editing the store.
	dropInDir := filepath.Join(r.layout.ConfigDir, "config.d")
	for _, dir := range []string{r.layout.ConfigDir, dropInDir} {
		made, err := r.fs.ensureDir(dir, 0o755, 0, 0, true)
		if err != nil {
			return err
		}
		changed = changed || made
	}

	// The drop-ins already there, for the same reason.  A root-owned directory
	// stops one being created or unlinked and does nothing about writing to a
	// file that is already in it, and every one of these merges into the config
	// that decides what the executor runs.
	dropIns, err := os.ReadDir(dropInDir)
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	for _, entry := range dropIns {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".toml") {
			continue
		}
		made, err := r.fs.ensureOwnership(filepath.Join(dropInDir, entry.Name()), 0o644, 0, 0)
		if err != nil {
			return err
		}
		changed = changed || made
	}

	// The age key's directory is the config directory, made just above, so there
	// is nothing to create here.  What protects the key is its own 0400 keeper
	// ownership, not the mode of what it sits in.

	// The store: 2750 root with the store group, which holds the keeper and the
	// broker and nobody else.  The operator is deliberately not in it, so
	// reading or editing a managed file needs sudo.  The group that admits a
	// caller to the broker socket is a different one: asking for a value by
	// name is what an agent is for, and reading or replacing the file it comes
	// from is not, so one group cannot grant both.
	//
	// setgid so a file created here belongs to the store group rather than to
	// whoever ran sudo.  Group read and traverse without write, because the
	// keeper only decrypts and the broker only stats; nothing that reads these
	// needs to change them.
	//
	// Owned by root rather than by the operator, because owning the directory
	// is permission to unlink and rename what is in it whatever the files
	// themselves are, and that is the whole of what an operator-owned parent
	// would give away.
	storeChanged, err := r.fs.ensureDir(r.layout.SecretsDir, 0o2750|os.ModeSetgid, 0, r.storeGID, true)
	if err != nil {
		return err
	}
	changed = changed || storeChanged

	// The files already in it, handed to the store group along with the
	// directory.  An install that moved the group without this leaves them
	// owned by the operator and grouped to the client group, which the keeper
	// is no longer in: the directory would be right, every managed file would
	// be unreadable to the account that has to decrypt it, and the broker would
	// refuse to start rather than come up redacting nothing.
	//
	// Ownership only, contents untouched.  These are ciphertext this install
	// has no key for, and rewriting one would destroy it.
	//
	// A dry run is the one case that legitimately runs unprivileged, and now
	// that the store belongs to the store group the operator is not in, it is
	// also a directory the operator cannot look inside.  Reported as no change
	// rather than as a failure, so `faramir init --dry-run` still answers for
	// everything else, exactly as ensureDir does above.
	entries, err := os.ReadDir(r.layout.SecretsDir)
	switch {
	case r.opts.DryRun && errors.Is(err, os.ErrPermission):
		entries = nil
	case err != nil && !os.IsNotExist(err):
		return err
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		made, err := r.fs.ensureOwnership(
			filepath.Join(r.layout.SecretsDir, entry.Name()), 0o640, 0, r.storeGID)
		if err != nil {
			return err
		}
		storeChanged = storeChanged || made
		changed = changed || made
	}

	// A process takes its supplementary groups at exec and never re-reads them,
	// so a store that has just changed group is one the running keeper and
	// broker still hold the old gid for.  They keep reading it until something
	// restarts them and then cannot, which is a broker that was healthy at
	// install time and refuses at the next activation, for a reason by then
	// several days old.  Moving a store group is otherwise two steps that have
	// to agree and only one of them is here.
	if storeChanged {
		r.restartFor("store ownership")
	}

	// Created but not re-asserted, like the service homes: LogsDirectory= on the
	// broker's unit makes systemd apply LogsDirectoryMode here on every start,
	// so a mode asserted here is undone by the next start and reported as a
	// change on every run after that.
	made, err := r.fs.ensureDir(r.layout.LogDir, 0o750, r.brokerUID, r.brokerGID, false)
	if err != nil {
		return err
	}
	changed = changed || made

	r.step("directories", changed, fmt.Sprintf("%s, %s, %s",
		r.layout.ConfigDir, r.layout.SecretsDir, r.layout.LogDir))
	return nil
}

// stepBinaries installs the binaries, the agent hook and the docs.
func (r *runner) stepBinaries() error {
	changed := false
	for _, name := range installedBinaries {
		made, err := r.fs.copyFile(filepath.Join(r.opts.Binaries, name),
			filepath.Join(r.layout.BinDir, name), 0o755, 0, 0)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	if _, err := r.fs.ensureDir(r.layout.LibexecDir, 0o755, 0, 0, true); err != nil {
		return err
	}
	made, err := r.fs.copyFile(r.guardSource(),
		filepath.Join(r.layout.LibexecDir, "faramir-guard"), 0o755, 0, 0)
	if err != nil {
		return err
	}
	changed = changed || made

	// Next to the hook rather than under the config directory, so they travel
	// with the thing that reads them.  A patterns file the hook cannot find is
	// worse than none: it falls back to a built-in list that is silently weaker.
	// wrap.sh is sourced by the shell the hook rewrites into, so it is read,
	// never executed.
	// The patterns are rendered rather than copied, because which paths are
	// worth refusing is a property of this install and not of the source tree:
	// an operator who moved the config and the store into a home gets rules
	// naming where they actually are, instead of the compiled defaults.  The
	// built-in fallback keeps those defaults, so a hook that cannot find this
	// file still refuses something.
	patterns, err := render("agent/hooks/deny-patterns.txt", r.layout)
	if err != nil {
		return err
	}
	made, err = r.fs.writeFile(filepath.Join(r.layout.LibexecDir, "deny-patterns.txt"),
		patterns, 0o644, 0, 0)
	if err != nil {
		return err
	}
	changed = changed || made

	// wrap.sh is sourced by the shell the hook rewrites into, so it is read,
	// never executed, and it names no install path.
	made, err = r.writeAsset("agent/hooks/wrap.sh",
		filepath.Join(r.layout.LibexecDir, "wrap.sh"), 0o644)
	if err != nil {
		return err
	}
	changed = changed || made

	docs, err := r.installDocs()
	if err != nil {
		return err
	}
	if changed {
		r.restartFor("binaries")
	}
	r.step("binaries", changed || docs, fmt.Sprintf("%s, hook in %s",
		r.layout.BinDir, r.layout.LibexecDir))
	return nil
}

func (r *runner) installDocs() (bool, error) {
	if _, err := r.fs.ensureDir(r.layout.DocDir, 0o755, 0, 0, true); err != nil {
		return false, err
	}
	changed, err := r.writeAsset("README.md", filepath.Join(r.layout.DocDir, "README.md"), 0o644)
	if err != nil {
		return false, err
	}
	entries, err := fs.ReadDir(faramir.Assets, "docs")
	if err != nil {
		return false, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		made, err := r.writeAsset("docs/"+entry.Name(),
			filepath.Join(r.layout.DocDir, entry.Name()), 0o644)
		if err != nil {
			return false, err
		}
		changed = changed || made
	}
	return changed, nil
}

// readAsset reads one embedded file.
func readAsset(assetPath string) ([]byte, error) {
	data, err := faramir.Assets.ReadFile(assetPath)
	if err != nil {
		return nil, fmt.Errorf("embedded asset %s: %w", assetPath, err)
	}
	return data, nil
}

// writeAsset copies an embedded file out verbatim.
func (r *runner) writeAsset(assetPath, dst string, mode os.FileMode) (bool, error) {
	data, err := readAsset(assetPath)
	if err != nil {
		return false, err
	}
	return r.fs.writeFile(dst, data, mode, 0, 0)
}

// stepConfig installs the base config.
//
// An existing one is kept and the new default written to config.toml.dist
// beside it, because that file is where an operator edits by hand.  Settings
// belonging to a consumer of the broker go in config.d/*.toml instead, which
// merge over this and can be reconciled on every run.
func (r *runner) stepConfig() error {
	body, err := render("etc/config.toml.tmpl", r.layout)
	if err != nil {
		return err
	}
	// root:root wherever it sits, for the reason stepDirectories gives: this
	// file and the drop-ins beside it decide what the executor runs, so an
	// account that can rewrite one can choose what receives a secret.
	owner, group := 0, 0
	if exists(r.layout.ConfigFile) && !r.opts.OverwriteConfig {
		changed, err := r.fs.writeFile(r.layout.ConfigFile+".dist", body, 0o644, owner, group)
		if err != nil {
			return err
		}
		// Kept, but not left in the operator's hands.  Its contents are theirs
		// to edit; its ownership is not, because a root-owned directory stops a
		// drop-in being created and does nothing about writing to a file that is
		// already there, and this is the file [exec.base_env] lives in.
		owned, err := r.fs.ensureOwnership(r.layout.ConfigFile, 0o644, owner, group)
		if err != nil {
			return err
		}
		changed = changed || owned
		r.step("config", changed, fmt.Sprintf("keeping %s; new default at %s.dist",
			r.layout.ConfigFile, r.layout.ConfigFile))
		return nil
	}
	changed, err := r.fs.writeFile(r.layout.ConfigFile, body, 0o644, owner, group)
	if err != nil {
		return err
	}
	if changed {
		r.restartFor("config")
	}
	r.step("config", changed, r.layout.ConfigFile)
	return nil
}

// initDropIn is the drop-in init owns.  Named to sort before a consumer's, so a
// list it contributes to accumulates in a predictable order.
const initDropIn = "00-faramir-init.toml"

// stepInitDropIn names the SSH key init generated.
//
// A drop-in rather than the base config, for the reason every reconcilable
// setting is one: init keeps an existing config.toml, so a key named there
// would land on a first install and never be reconciled again.  Not the base
// config's [ssh] keys either, which stays empty on purpose.
//
// This is init's own, as against a consumer's: generating a key the broker is
// never told to load leaves an agent holding nothing and every brokered command
// unable to reach a host, which the validation step then fails the run over.
// Removed when --ssh-key is not given, so dropping the flag actually drops the
// key rather than leaving the last run's still configured.
func (r *runner) stepInitDropIn() error {
	path := filepath.Join(r.layout.ConfigDir, "config.d", initDropIn)
	if r.opts.SSHKey == "" {
		removed, err := r.fs.remove(path)
		if err != nil {
			return err
		}
		if removed {
			r.restartFor("config")
		}
		r.step("init drop-in", removed, "no --ssh-key, so [ssh] keys stays empty")
		return nil
	}
	body := fmt.Sprintf(`# Written by faramir init. Merged over config.toml, which leaves these empty
# on purpose so that a re-run can reconcile them and an edit here is not lost.
[ssh]
keys = ["%s"]
`, r.opts.SSHKey)
	changed, err := r.fs.writeFile(path, []byte(body), 0o644, 0, 0)
	if err != nil {
		return err
	}
	if changed {
		r.restartFor("config")
	}
	r.step("init drop-in", changed, path)
	return nil
}

// stepUnits writes the systemd units and the tmpfiles entry.
//
// Rendered from the same Layout as the config, which is what makes the group
// and the uids in one agree with the other.  There are no drop-ins: the
// keeper's sandbox and its credential source are conditionals inside the unit,
// so reverting either is a re-run without the flag rather than a file somebody
// has to remember to delete.
func (r *runner) stepUnits() error {
	changed := false
	for _, name := range unitNames() {
		body, err := render(units[name], r.layout)
		if err != nil {
			return err
		}
		made, err := r.fs.writeFile(filepath.Join("/etc/systemd/system", name), body, 0o644, 0, 0)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	// Nothing here removes a drop-in from an earlier arrangement.  init installs;
	// it does not migrate.  A host carrying state from a previous layout is
	// reconciled by whatever provisions it, with a task that can be deleted once
	// every host has run it, which is a thing a version of this command cannot
	// know and would carry forever.
	body, err := render("systemd/faramir.tmpfiles.conf.tmpl", r.layout)
	if err != nil {
		return err
	}
	made, err := r.fs.writeFile("/etc/tmpfiles.d/faramir.conf", body, 0o644, 0, 0)
	if err != nil {
		return err
	}
	if changed || made {
		r.restartFor("units")
	}
	r.step("units", changed || made, strings.Join(unitNames(), ", "))
	return nil
}

// stepReachable makes the directories the daemons read enterable by them.
//
// Before the units are written and long before anything is started.  A home is
// 0700, so a config kept in one is invisible to all three service uids, and a
// daemon whose config it cannot open exits 2 before it opens a socket: the
// restart fails, the run aborts, and a re-run aborts in the same place.
//
// Traversal only, never Share: the config and the store are read by the daemons
// and written by the operator, and a config a brokered command could rewrite is
// the policy rewriting itself.  The store's own group-write comes from its mode,
// set where it is created.
func (r *runner) stepReachable() error {
	if r.opts.DryRun {
		r.skip("reachable", "dry run")
		return nil
	}
	var granted []string
	for _, dir := range []string{r.layout.ConfigDir, r.layout.SecretsDir} {
		if homeOf(dir) == "" {
			continue
		}
		if err := sharetree.Reachable(sharetree.Options{
			Dir: dir, Operator: r.opts.Operator, Group: r.layout.Group,
		}); err != nil {
			return fmt.Errorf("%s: %w", dir, err)
		}
		granted = append(granted, dir)
	}
	if len(granted) == 0 {
		r.skip("reachable", "nothing the daemons read is inside a home")
		return nil
	}
	// Reported as no change: it re-applies a group and an execute bit that are
	// already what they should be on every run after the first.
	r.step("reachable", false, strings.Join(granted, ", "))
	return nil
}
