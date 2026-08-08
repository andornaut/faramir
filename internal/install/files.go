package install

import (
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

// requiredBinaries is what preflight demands, which is every binary the install
// copies rather than only the ones going to BinDir.  A source directory missing
// the hook would otherwise pass the check and fail at the copy, after the
// accounts, the age key and the SSH key had already been created.
var requiredBinaries = append(append([]string{}, installedBinaries...), "faramir-guard")

// stepDirectories creates what everything below writes into.
func (r *runner) stepDirectories() error {
	changed := false

	// 0755 root:root: the broker, the keeper and the agent all read the config
	// from here, so the directory cannot belong to any one of them.  An
	// operator's own home is the exception, where the home's owner keeps it and
	// edits their config without sudo; the daemons only ever read it.
	//
	// own=false on both, so a directory that is already there keeps whatever
	// the operator set up.  Re-owning one unconditionally is how a config
	// directory inside a home comes back root-owned and no longer theirs.
	configUID, configGID := 0, 0
	if homeOf(r.layout.ConfigDir) != "" {
		configUID, configGID = r.operatorUID, keep
	}
	for _, dir := range []string{r.layout.ConfigDir, filepath.Join(r.layout.ConfigDir, "config.d")} {
		made, err := r.fs.ensureDir(dir, 0o755, configUID, configGID, false)
		if err != nil {
			return err
		}
		changed = changed || made
	}

	// The age key's directory, which is not under ConfigDir when that has been
	// moved into a home.  0755 root:root; what protects the key is its own mode.
	made, err := r.fs.ensureDir(r.layout.AgeKeyDir(), 0o755, 0, 0, false)
	if err != nil {
		return err
	}
	changed = changed || made

	// The store: 2770 root with the shared group, so the operator edits it with
	// sops and the keeper decrypts it, both through the group and neither
	// needing sudo.  setgid so a file either of them creates stays readable by
	// the other.  The ciphertext's own mode is what sops writes; what keeps it
	// secret is the age key, which is not here.
	//
	// Owned by root rather than by the operator: group write is what they need
	// to edit a file in it, and owning the directory would additionally let them
	// change its mode, which is the one thing keeping the keeper's access from
	// being revoked by accident.
	made, err = r.fs.ensureDir(r.layout.SecretsDir, 0o2770|os.ModeSetgid, 0, r.groupGID, true)
	if err != nil {
		return err
	}
	changed = changed || made

	// Created but not re-asserted, like the service homes: LogsDirectory= on the
	// broker's unit makes systemd apply LogsDirectoryMode here on every start,
	// so a mode asserted here is undone by the next start and reported as a
	// change on every run after that.
	made, err = r.fs.ensureDir(r.layout.LogDir, 0o750, r.brokerUID, r.brokerGID, false)
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
	made, err := r.fs.copyFile(filepath.Join(r.opts.Binaries, "faramir-guard"),
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
	for _, asset := range []string{"agent/hooks/deny-patterns.txt", "agent/hooks/wrap.sh"} {
		made, err := r.writeAsset(asset, filepath.Join(r.layout.LibexecDir, filepath.Base(asset)), 0o644)
		if err != nil {
			return err
		}
		changed = changed || made
	}

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
	owner, group := 0, 0
	if homeOf(r.layout.ConfigDir) != "" {
		owner, group = r.operatorUID, r.groupGID
	}
	if exists(r.layout.ConfigFile) && !r.opts.OverwriteConfig {
		changed, err := r.fs.writeFile(r.layout.ConfigFile+".dist", body, 0o644, owner, group)
		if err != nil {
			return err
		}
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
