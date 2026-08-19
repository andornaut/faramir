package install

// The sudo grant `faramir init --allow-sudo` writes. What it is for is
// docs/escalation.md; what it must keep saying:
//
//   - PASSWD, never NOPASSWD. A passwordless grant is usable with the broker
//     out of the way, which is a brokered command skipping the escalation.
//   - A PAM service of faramir's own, named by the entry's `pam_service`, so a
//     mistake here leaves every other sudo on the host alone.
//
// Re-running init without --allow-sudo takes the grant away: the file goes and
// the account's password is locked.

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// stepSudoGrant writes or removes the grant: a sudoers entry and the PAM
// service it names. There is no credential to place: sudo authenticates the
// executor's account against a service whose auth step asks the broker, so an
// escalation is a decision rather than a value.
//
// After stepConfig, which renders [escalation] from the same layout, and before
// anything restarts a daemon.
func (r *runner) stepSudoGrant() error {
	if !r.layout.AllowSudo {
		return r.revokeSudoGrant()
	}
	if r.opts.DryRun {
		r.step("sudo grant", !exists(sudoersFile), "would grant "+r.layout.ExecUser+
			" sudo, authenticated by "+r.layout.PamFile())
		return nil
	}
	if !exists(sudoersDir) || !exists(pamDir) {
		// A host with no sudo, or no PAM. Reported rather than failed: the rest of
		// the install works.
		r.warnf("%s or %s does not exist, so no grant was written and brokered "+
			"commands cannot sudo here. Install sudo, then re-run this install",
			sudoersDir, pamDir)
		r.skip("sudo grant", "no "+sudoersDir+" or "+pamDir)
		return nil
	}

	// The PAM service first: a sudoers entry naming a service that is not there
	// sends sudo to /etc/pam.d/other, which asks for a password nothing
	// supplies.
	pam, err := render("etc/pam.d.tmpl", r.layout)
	if err != nil {
		return err
	}
	// 0644 root:root, as every file in /etc/pam.d is: an account that could write
	// it would be choosing how it authenticates.
	authChanged, err := r.fs.writeFile(r.layout.PamFile(), pam, 0o644, 0, 0)
	if err != nil {
		return err
	}

	body, err := render("etc/sudoers.tmpl", r.layout)
	if err != nil {
		return err
	}
	// 0440 root:root, which is what sudo requires of a file in sudoers.d.
	granted, err := r.fs.writeFile(sudoersFile, body, 0o440, 0, 0)
	if err != nil {
		return err
	}
	if granted {
		if err := r.validateSudoers(); err != nil {
			return err
		}
	}
	// The account authenticates through the broker and never with a password, so
	// a usable hash would be a second way in that the broker is not asked about.
	// Re-asserted every run.
	if _, err := r.command("usermod", "-L", r.layout.ExecUser); err != nil {
		r.warnf("could not lock %s's password (%v); it authenticates through the "+
			"broker and should hold no password of its own: usermod -L %s",
			r.layout.ExecUser, err, r.layout.ExecUser)
	}
	// An earlier layout kept a password for this. Removed rather than left: a
	// credential that authenticates nothing is still a credential.
	for _, stale := range []string{
		filepath.Join(r.layout.RunDir, "elevate.secret"),
		filepath.Join(r.layout.ConfigDir, "elevate.secret"),
	} {
		if exists(stale) {
			if err := os.Remove(stale); err != nil {
				return err
			}
			r.warnf("removed %s, left by an earlier install: escalation no longer uses "+
				"a password at all", stale)
		}
	}

	if granted || authChanged {
		r.restartFor("sudo grant")
	}
	r.step("sudo grant", granted || authChanged, fmt.Sprintf(
		"%s may ask to sudo on this host; %s answers, one escalation per command",
		r.layout.ExecUser, r.layout.PamFile()))
	return nil
}

// revokeSudoGrant is what an install without --allow-sudo does: it removes what
// an install with it wrote, and leaves the account locked.
func (r *runner) revokeSudoGrant() error {
	stale := []string{
		sudoersFile,
		pamServiceFile,
		// Where earlier layouts kept a password.
		filepath.Join(r.layout.RunDir, "elevate.secret"),
		filepath.Join(r.layout.ConfigDir, "elevate.secret"),
	}
	found := false
	for _, path := range stale {
		if exists(path) {
			found = true
		}
	}
	if !found {
		// Never enabled, which is every default install: nothing to report.
		return nil
	}
	if r.opts.DryRun {
		r.step("sudo grant", true, "would revoke "+sudoersFile+
			": --allow-sudo was not passed, and this host has the grant")
		return nil
	}
	for _, path := range stale {
		if !exists(path) {
			continue
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	// Locking rather than clearing: an account with an empty password field is one
	// some PAM stacks let in without asking.
	if _, err := r.command("usermod", "-L", r.layout.ExecUser); err != nil {
		r.warnf("could not lock %s's password (%v); the grant is gone, so nothing "+
			"can sudo, but lock it by hand: usermod -L %s",
			r.layout.ExecUser, err, r.layout.ExecUser)
	}
	r.restartFor("sudo grant")
	r.step("sudo grant", true, "revoked: "+sudoersFile+" and the PAM service "+
		"removed, because --allow-sudo was not passed")
	return nil
}

// validateSudoers has visudo judge what was written, and takes it back out
// again if visudo will not have it: a malformed file in sudoers.d is a host
// where nobody can sudo at all.
func (r *runner) validateSudoers() error {
	path, err := exec.LookPath("visudo")
	if err != nil {
		// Reported rather than failed: the file is generated from a template with no
		// operator input in it, so the risk this covers is a sudo too old for a
		// directive rather than a typo.
		r.warnf("visudo is not installed, so %s went unchecked; verify it with "+
			"`visudo -cf %s` on a host that has it", sudoersFile, sudoersFile)
		return nil //nolint:nilerr // no visudo is a warning, not a failed install
	}
	if out, err := exec.CommandContext(context.Background(), path, "-cf", sudoersFile).
		CombinedOutput(); err != nil {
		removeErr := os.Remove(sudoersFile)
		return fmt.Errorf("visudo rejected %s, so it was removed again (%w): %w: %s",
			sudoersFile, removeErr, err, strings.TrimSpace(string(out)))
	}
	return nil
}
