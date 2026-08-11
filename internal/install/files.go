package install

import (
	"errors"
	"fmt"
	"io/fs"
	"maps"
	"os"
	"path/filepath"
	"slices"
	"strings"

	faramir "github.com/andornaut/faramir"
	"github.com/andornaut/faramir/internal/sharetree"
)

// installedBinaries goes to BinDir.  There is one; the daemons, the MCP server
// and the hook are subcommands of it.  LibexecDir holds the hook's deny list
// and wrap script.
var installedBinaries = []string{"faramir"}

// legacyBinaries is what an earlier layout installed, one binary per role. Only
// uninstall names them: init installs and never migrates, but a teardown has to
// leave nothing behind.  DefaultLibexecDir is removed wholesale.
var legacyBinaries = []string{
	"faramir-broker", "faramir-keeper", "faramir-exec", "faramir-mcp",
}

// stepDirectories creates what everything below writes into.
func (r *runner) stepDirectories() error {
	changed := false

	// 0755 root:root, including inside an operator's own home: whoever can write a
	// drop-in chooses what the executor runs when a command names a bare program,
	// and it runs with the requested secret in its environment. An agent runs as
	// the operator, so operator-writable hands that choice to the agent. own=true,
	// so a directory already operator-owned is taken back.
	dropInDir := filepath.Join(r.layout.ConfigDir, "config.d")
	for _, dir := range []string{r.layout.ConfigDir, dropInDir} {
		made, err := r.fs.ensureDir(dir, 0o755, 0, 0, true)
		if err != nil {
			return err
		}
		changed = changed || made
	}

	// The drop-ins already there: a root-owned directory stops one being created
	// or unlinked, not one being written to.
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

	// The age key sits in the config directory, made above.  What protects it is
	// its own 0400 keeper ownership.

	// The secrets directory: 2750 root with the secrets group, the keeper's own,
	// which holds the one account that opens a managed file.  The operator is not
	// in it, so editing one needs sudo, and the group admitting a caller to the
	// broker socket is a different one.
	//
	// setgid, so a file created here belongs to the secrets group rather than to
	// whoever ran sudo.  Group read and traverse without write, the keeper only
	// decrypting and fingerprinting.  Owned by root, since owning the directory is
	// permission to unlink and rename what is in it.
	storeChanged, err := r.fs.ensureDir(r.layout.SecretsDir(), 0o2750|os.ModeSetgid, 0, r.secretsGID, true)
	if err != nil {
		return err
	}
	changed = changed || storeChanged

	// The files already in it, handed to the secrets group with the directory:
	// without this they stay grouped to the client group, which the keeper is not
	// in, and every managed file is unreadable to the account that decrypts it.
	//
	// Ownership only.  These are ciphertext this install has no key for.
	//
	// A dry run runs unprivileged and cannot look inside, so it reports no change
	// rather than a failure, as ensureDir does above.
	entries, err := os.ReadDir(r.layout.SecretsDir())
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
			filepath.Join(r.layout.SecretsDir(), entry.Name()), 0o640, 0, r.secretsGID)
		if err != nil {
			return err
		}
		storeChanged = storeChanged || made
		changed = changed || made
	}

	// Supplementary groups are taken at exec and never re-read, so a running
	// keeper and broker hold the old gid until something restarts them, so a
	// broker healthy at install time would otherwise refuse at the next
	// activation, days later.
	if storeChanged {
		r.restartFor("secrets ownership")
	}

	// Created but not re-asserted: LogsDirectory= on the broker's unit applies
	// LogsDirectoryMode on every start, so a mode set here would be undone and
	// reported as a change on every run.
	made, err := r.fs.ensureDir(r.layout.LogDir, 0o750, r.brokerUID, r.brokerGID, false)
	if err != nil {
		return err
	}
	changed = changed || made

	// The log file itself, not only the directory it sits in: whoever writes the
	// first record creates it, and `faramir edit` runs as root, so on a fresh host
	// the log lands root-owned and every later append from the broker fails.
	// audit.Write deliberately never fails a request, so that is silent.
	// logrotate re-creates it broker-owned, which covers every file after this
	// one.
	made, err = r.fs.ensurePrivateFile(r.layout.AuditLogPath(), r.brokerUID, r.brokerGID)
	if err != nil {
		return err
	}
	changed = changed || made

	r.step("directories", changed, fmt.Sprintf("%s, %s, %s",
		r.layout.ConfigDir, r.layout.SecretsDir(), r.layout.LogDir))
	return nil
}

// stepBinaries installs the binaries, the agent hook and the docs.
func (r *runner) stepBinaries() error {
	changed := false
	for _, name := range installedBinaries {
		made, err := r.fs.copyFile(filepath.Join(r.binaries, name),
			filepath.Join(r.layout.BinDir, name), 0o755, 0, 0)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	if _, err := r.fs.ensureDir(r.layout.LibexecDir, 0o755, 0, 0, true); err != nil {
		return err
	}

	// Beside the hook rather than under the config directory, so they travel with
	// what reads them.  The patterns are rendered rather than copied, since which
	// paths are worth refusing belongs to this install: an operator who moved the
	// config directory gets rules naming where it is.  A hook that cannot find the
	// file falls back to the compiled defaults.
	patterns, err := render("agent/hooks/deny-patterns.txt", r.layout)
	if err != nil {
		return err
	}
	made, err := r.fs.writeFile(filepath.Join(r.layout.LibexecDir, "deny-patterns.txt"),
		patterns, 0o644, 0, 0)
	if err != nil {
		return err
	}
	changed = changed || made

	// Sourced by the shell the hook rewrites into, so read and never executed, and
	// it names no install path.
	made, err = r.writeAsset("agent/hooks/wrap.sh",
		filepath.Join(r.layout.LibexecDir, "wrap.sh"), 0o644)
	if err != nil {
		return err
	}
	changed = changed || made

	// What the PAM service execs to decide one sudo, rendered because it names the
	// binary and the account by path.  Installed on every host, a sudo grant or not:
	// without a PAM service and a sudoers entry nothing execs it, and leaving a
	// stale one behind would be worse than leaving one that does nothing.
	// Executable, unlike wrap.sh: PAM execs this, as root.
	helper, err := render("agent/hooks/pam-approve.tmpl", r.layout)
	if err != nil {
		return err
	}
	made, err = r.fs.writeFile(r.layout.PamHelper(), helper, 0o755, 0, 0)
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
	r.step("binaries", changed || docs, fmt.Sprintf("%s/faramir, hook data in %s",
		r.layout.BinDir, r.layout.LibexecDir))
	return nil
}

// installDocs lays the docs out the way the checkout does: README.md at the
// top, the rest under docs/.
func (r *runner) installDocs() (bool, error) {
	targets, err := docTargets(r.layout)
	if err != nil {
		return false, err
	}
	if _, err := r.fs.ensureDir(r.layout.DocDir, 0o755, 0, 0, true); err != nil {
		return false, err
	}
	if _, err := r.fs.ensureDir(filepath.Join(r.layout.DocDir, "docs"), 0o755, 0, 0, true); err != nil {
		return false, err
	}
	changed := false
	for _, asset := range slices.Sorted(maps.Keys(targets)) {
		made, err := r.writeAsset(asset, targets[asset], 0o644)
		if err != nil {
			return false, err
		}
		changed = changed || made
	}
	return changed, nil
}

// docTargets maps each embedded doc to the same path under the doc directory.
// Unchanged, because everything that cites a doc (Documentation=, the README's
// own links, the deny list, the plugins, `faramir edit`) cites it by the
// checkout's path.
func docTargets(layout Layout) (map[string]string, error) {
	targets := map[string]string{
		"README.md": filepath.Join(layout.DocDir, "README.md"),
		// Beside the README: nothing cites it, and that is where a licence belongs.
		"LICENSE": filepath.Join(layout.DocDir, "LICENSE"),
	}
	entries, err := fs.ReadDir(faramir.Assets, "docs")
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".md") {
			continue
		}
		targets["docs/"+entry.Name()] = filepath.Join(layout.DocDir, "docs", entry.Name())
	}
	return targets, nil
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

// stepConfig writes the base config on every run.  Rewritten rather than kept:
// this file is faramir's, and everything an operator or consumer sets goes in a
// drop-in beside it that init never touches.
func (r *runner) stepConfig() error {
	body, err := render("etc/config.toml.tmpl", r.layout)
	if err != nil {
		return err
	}
	// root:root wherever it sits: this file and the drop-ins beside it decide what
	// the executor runs.
	owner, group := 0, 0
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

// stepUnits writes the systemd units and the tmpfiles entry, from the same
// Layout as the config so the uids and groups agree.  No drop-ins: the keeper's
// sandbox and credential source are conditionals inside the unit, so reverting
// either is a re-run without the flag.
func (r *runner) stepUnits() error {
	changed := false
	for _, name := range unitNames() {
		body, err := render(units[name], r.layout)
		if err != nil {
			return err
		}
		made, err := r.fs.writeFile(filepath.Join(systemUnitDir, name), body, 0o644, 0, 0)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	// Nothing here removes a drop-in from an earlier arrangement: init installs,
	// it does not migrate.
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
	return r.stepLogrotate()
}

// stepLogrotate bounds the audit log.  Its own step: nothing here is a unit and
// no daemon reads it, so a host managing its logs another way deletes this one
// file.
func (r *runner) stepLogrotate() error {
	body, err := render("etc/logrotate.conf.tmpl", r.layout)
	if err != nil {
		return err
	}
	made, err := r.fs.writeFile(logrotateConfig, body, 0o644, 0, 0)
	if err != nil {
		return err
	}
	r.step("logrotate", made, logrotateConfig)
	return nil
}

// stepReachable makes the config directory the daemons read enterable by them,
// before the units are written.  A home is 0700, so a config kept in one is
// invisible to all three service uids and every daemon exits 2 before opening a
// socket.
//
// The config directory alone, being 0755, which covers the secrets directory
// and the key inside it.  Traversal only, never Share: a config a brokered
// command could rewrite is the policy rewriting itself.
func (r *runner) stepReachable() error {
	if r.opts.DryRun {
		r.skip("reachable", "dry run")
		return nil
	}
	dir := r.layout.ConfigDir
	if homeOf(dir) == "" {
		r.skip("reachable", "nothing the daemons read is inside a home")
		return nil
	}
	if err := sharetree.Reachable(sharetree.Options{
		Dir: dir, Operator: r.opts.OperatorUser, Group: r.layout.ClientGroup,
	}); err != nil {
		return fmt.Errorf("%s: %w", dir, err)
	}
	// Reported as no change: after the first run it re-applies what is already
	// there.
	r.step("reachable", false, dir)
	return nil
}
