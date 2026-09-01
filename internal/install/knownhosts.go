package install

import (
	"fmt"
	"path/filepath"

	"github.com/andornaut/faramir/internal/knownhosts"
)

// stepKnownHosts pins the host keys a brokered ssh verifies against.
//
// A copy rather than a reference: the executor cannot read the operator's 0700
// ~/.ssh, and ssh names no environment variable for a known_hosts file. Safe
// where copying an ssh config is not, a known_hosts file being public keys with
// no directive that executes anything. Silent without --known-hosts.
//
// Replaced whole rather than merged: HashKnownHosts is on by default, so
// entries cannot be matched by name, and appending blind would keep a rotated
// host's old key as a second line ssh still accepts.
func (r *runner) stepKnownHosts() error {
	if r.opts.KnownHosts == "" {
		return nil
	}
	data, entries, err := knownhosts.Read(r.opts.KnownHosts)
	if err != nil {
		return err
	}
	path := r.layout.ExecKnownHosts()
	// The file is replaced whole, so pinning an empty one removes what is
	// there.
	if entries == 0 {
		r.warnf("%s holds no host keys, so this removes whatever %s had pinned and "+
			"leaves a brokered ssh verifying against %s alone. Re-run with a file that "+
			"holds the fleet's host keys, or leave --known-hosts out to keep what is pinned",
			r.opts.KnownHosts, path, knownhosts.GlobalFile)
	}
	// A dry run runs unprivileged and cannot look inside the executor's 0700
	// home. Reported as a change, which does not call an install current when it
	// is not.
	if r.opts.DryRun {
		r.step("known hosts", true, fmt.Sprintf("pin %d host key(s) from %s in %s",
			entries, r.opts.KnownHosts, path))
		return nil
	}
	// Created by the accounts step; asserted here so a run after it was removed
	// by hand writes into a directory with the mode it needs.
	made, err := r.fs.EnsureDir(filepath.Dir(path), 0o700, r.execUID, r.execGID, true)
	if err != nil {
		return err
	}
	// World-readable like the other public halves this installs, and the
	// executor's own: the home above it is 0700.
	changed, err := r.fs.WriteFile(path, data, 0o644, r.execUID, r.execGID)
	if err != nil {
		return err
	}
	r.step("known hosts", changed || made,
		fmt.Sprintf("%s, %d host key(s) from %s", path, entries, r.opts.KnownHosts))
	return nil
}
