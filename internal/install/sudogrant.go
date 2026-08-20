package install

// The sudo grant `faramir init --allow-sudo` writes. What it is for is
// docs/escalation.md; what it must keep saying:
//
//   - PASSWD, never NOPASSWD. A passwordless grant is usable with the broker
//     out of the way, which is a brokered command skipping the escalation.
//   - A PAM service of faramir's own, so a mistake in what decides an escalation
//     reaches the executor and no other account.
//
// What selects that service is the one thing the two sudo implementations do not
// share. The original takes `pam_service` and `pam_login_service` in the entry
// below, and faramir touches nothing else. sudo-rs has neither and compiles in
// the service names `sudo` and `sudo-i`, so there the selection is a delimited
// branch in those two stacks: see pamsudo.go. Which arrangement a host gets is
// probed rather than configured, and doctor re-asks on every run.
//
// Re-running init without --allow-sudo takes the grant away: the files go, the
// branch comes out, and the account's password is locked.

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
		// Named for the arrangement this host would get: there is no PamFile on a
		// sudo-rs host, so naming it would send an operator to a path init is not
		// going to write.
		stack := r.layout.PamFile()
		if r.layout.SudoRs {
			stack = "a faramir block in " + r.layout.SudoPamFile()
		}
		r.step("sudo grant", !exists(sudoersFile), "would grant "+r.layout.ExecUser+
			" sudo, authenticated by "+stack)
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
	// sends sudo to /etc/pam.d/other, which asks for a password nothing supplies.
	//
	// Only on a host whose sudo is the original, which is the only one that can be
	// sent here. Under sudo-rs the same stack is written into the shared files
	// behind a branch on the account, and a service file beside it would be one
	// nothing reads: see writeSudoPamBlock.
	authChanged, err := r.syncPamService()
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

	// The branch in the stacks every account's sudo reads, LAST of the three and
	// only once the grant is on disk and visudo has taken it. A rejection above
	// removes the grant and fails the run, and a block written before that point
	// would outlive it: a branch in a shared file on a host that was granted
	// nothing.
	//
	// The other side removes a block rather than skipping one: an install that
	// wrote it and an operator who has since switched the `sudo` alternatives
	// group would otherwise leave a branch in a stack the host's sudo no longer
	// reads that way.
	var branchChanged bool
	if r.layout.SudoRs {
		branchChanged, err = r.writeSudoPamBlock()
	} else {
		branchChanged, err = removeSudoPamBlock(r.fs)
	}
	if err != nil {
		return err
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

	if granted || authChanged || envChanged || branchChanged {
		r.restartFor("sudo grant")
	}
	// The sentence names what selects the service, that being the whole of the
	// difference between the two arrangements and the thing an operator has to
	// know before reading /etc/pam.d.
	answers := r.layout.PamFile() + ", selected by " + r.layout.SudoersFile() +
		"'s pam_service"
	if r.layout.SudoRs {
		answers = "a faramir block in " + r.layout.SudoPamFile() +
			", this host's sudo being sudo-rs and reaching no service a caller may name"
	}
	r.step("sudo grant", granted || authChanged || envChanged || branchChanged, fmt.Sprintf(
		"%s may ask to sudo on this host; %s answers, one escalation per command",
		r.layout.ExecUser, answers))
	return nil
}

// syncPamService writes faramir's own service file, or removes one that should
// not be there.
//
// It should be there only on a host whose sudo is the original, that being the
// only one that can be sent to a service by name. Under sudo-rs the same stack
// is the block in the shared files, and a service file beside it is one nothing
// reads: left behind by an install made before the `sudo` alternatives group was
// switched, and misleading to anyone who finds it.
func (r *runner) syncPamService() (bool, error) {
	if r.layout.SudoRs {
		if !exists(r.layout.PamFile()) {
			return false, nil
		}
		return true, os.Remove(r.layout.PamFile())
	}
	pam, err := render("etc/pam.d.tmpl", r.layout)
	if err != nil {
		return false, err
	}
	// 0644 root:root, as every file in /etc/pam.d is: an account that could write
	// it would be choosing how it authenticates.
	return r.fs.writeFile(r.layout.PamFile(), pam, 0o644, 0, 0)
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
	// The branch in the shared stacks counts as the grant being here: a host whose
	// files were removed by hand and whose /etc/pam.d/sudo still carries a branch
	// has something left to take out.
	//
	// An error reading those files is not one: every install that grants nothing
	// reaches this, which is most of them, and none of them should fail over a
	// /etc/pam.d this run cannot read. Treated as nothing to remove, and the
	// removal below says so if there was.
	branched, _ := sudoPamBlockPresent()
	if !found && !branched {
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
	if _, err := removeSudoPamBlock(r.fs); err != nil {
		// Reported rather than fatal, and named: the grant's own files are gone by
		// now, so nothing can sudo either way, but a branch left in a shared stack
		// is a line pointing at a helper this run deleted.
		r.warnf("the faramir block could not be taken out of a shared PAM stack "+
			"(%v). The grant is gone, so nothing can escalate, but remove the lines "+
			"between %q and %q by hand", err, pamBlockBegin, pamBlockEnd)
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
// sudo builds. Root's, 0644: PAM reads it as root through the pam_env line in
// faramir's own service, and the executor's uid must not be able to write what
// root will be handed.
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
		// What env_refs refuses, refused here too. What PAM hands back is not put
		// through env_keep or env_check, so a name that redirects the loader, the
		// interpreter or sops reaches root through it -- and sudo's own env_reset used
		// to strip exactly these before this file existed.
		if protocol.ReservedEnv[name] {
			// Quietly for the ones sudo sets itself. PATH is a [command] env default,
			// so warning about it would put a line on every clean install that names
			// nothing the operator did and nothing they can act on -- and this is the
			// same channel that has to carry a '#' in a value or a name that is not a
			// name. sudo sets these over whatever PAM handed back, so leaving them out
			// changes nothing either way.
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
