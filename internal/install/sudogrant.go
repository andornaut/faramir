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

	"github.com/andornaut/faramir/internal/protocol"
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

	// Before the sudoers entry that names it: an entry pointing at a file that is
	// not there makes sudo warn on every call, and validateSudoers below reads it.
	envChanged, err := r.writeSudoEnv()
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

	if granted || authChanged || envChanged {
		r.restartFor("sudo grant")
	}
	r.step("sudo grant", granted || authChanged || envChanged, fmt.Sprintf(
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
		r.layout.SudoEnvFile(),
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

// writeSudoEnv renders what a brokered command's sudo is given on top of what
// sudo builds. Root's, 0644: sudoers reads it as part of the policy, and the
// executor's uid must not be able to write what root will be handed.
//
// A value carrying a newline would be a second variable this file never named,
// so one is refused rather than written -- the operator is told, and the rest of
// the file is still correct.
func (r *runner) writeSudoEnv() (bool, error) {
	body, err := render("etc/sudo-env.tmpl", r.sudoEnv())
	if err != nil {
		return false, err
	}
	// No directory to make: this goes beside the PAM helper, in a directory the
	// install has already created by now. Nothing here makes a directory faramir
	// does not own outright, which is how a path it merely shares ends up deleted
	// by an uninstall that thinks it owns it.
	return r.fs.writeFile(r.layout.SudoEnvFile(), body, 0o644, 0, 0)
}

// sudoSetsItself is the reserved names sudo fills in on its own: PATH from
// secure_path and HOME from the target user. Left out of the file like the rest,
// but without a word about it, an entry sudo would ignore being nothing for an
// operator to fix.
var sudoSetsItself = map[string]bool{"PATH": true, "HOME": true}

// sudoEnv is the layout with [command] env cut down to what may be handed to
// root. Split out so the filter is what a test exercises: it is the only thing
// standing between that setting and root's environment, sudoers reading this
// file without env_keep or env_check.
func (r *runner) sudoEnv() Layout {
	safe := map[string]string{}
	for name, value := range r.layout.CommandEnv {
		// The name first, and against what an environment variable may be called
		// rather than against a list of characters: --command-env splits on the
		// first '=', so everything after one in the name arrives here as part of the
		// name, and a newline there renders a second line this file never named.
		// sudo skips the line without an '=' and applies the one after it.
		if !protocol.ValidEnvName(name) {
			r.warnf("[command] env %q is not a variable name, so it is left out of %s: "+
				"what follows the first '=' is the value, and anything else in the name "+
				"would be read as another variable", name, r.layout.SudoEnvFile())
			continue
		}
		// The same for the value, which ends its own line. '#' with it: sudo reads
		// this file with comments recognised anywhere on a line rather than only at
		// the start, so it keeps what precedes one and drops the rest. Left out
		// rather than written, because the harm is silence -- the run would hold the
		// whole value and its sudo a shorter one, and nothing would say so. Quoting
		// does not help: the value still truncates, and the opening quote survives
		// into it (measured on sudo 1.9.15p5).
		if strings.ContainsAny(value, "\n\r#") {
			r.warnf("[command] env %s is left out of %s: a value carrying a newline or "+
				"a '#' does not survive it whole, and a value that differs between a "+
				"command and its sudo is worse than one that is absent", name,
				r.layout.SudoEnvFile())
			continue
		}
		// What env_refs refuses, refused here too. sudoers reads this file without
		// env_keep or env_check, so a name that redirects the loader, the interpreter
		// or sops reaches root through it -- and sudo's own env_reset used to strip
		// exactly these before this file existed.
		if protocol.ReservedEnv[name] {
			// Quietly for the ones sudo sets itself. PATH is a [command] env default,
			// so warning about it would put a line on every clean install that names
			// nothing the operator did and nothing they can act on -- and this is the
			// same channel that has to carry a '#' in a value or a name that is not a
			// name. sudo adds an env_file entry only where it has not set one already,
			// so leaving these out changes nothing either way.
			if !sudoSetsItself[name] {
				r.warnf("[command] env %s is left out of %s: it is one of the names an "+
					"injected value may not carry either, and this file is read without "+
					"sudo's own environment checks", name, r.layout.SudoEnvFile())
			}
			continue
		}
		safe[name] = value
	}
	env := r.layout
	env.CommandEnv = safe
	return env
}
