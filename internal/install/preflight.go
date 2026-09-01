package install

// What a provisioning run refuses before it writes anything. A run that failed
// partway leaves a host in neither state, so every condition that can be
// established up front is established here.

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostsudo"
	"github.com/andornaut/faramir/internal/hostunit"
	"github.com/andornaut/faramir/internal/knownhosts"
)

// preflight refuses the run before anything is written, each of these otherwise
// surfacing with the install half applied.
func (r *runner) preflight() error {
	if os.Geteuid() != 0 && !r.opts.DryRun {
		return errors.New("faramir init must run as root: it creates accounts, " +
			"writes under /etc and installs systemd units")
	}
	if r.opts.AgentUser == "" || r.opts.AgentUser == "root" {
		// Reached by `block` and `link` as well, which have no flag of their own:
		// they read what the config records, and `init` is what records it.
		return errors.New("name the account the coding agent runs as: run through " +
			"sudo so SUDO_USER carries it, or record it with " +
			"`faramir init --agent-user`. It must not be root")
	}
	if !hostfs.UserExists(r.opts.AgentUser) {
		return fmt.Errorf("no such user: %s", r.opts.AgentUser)
	}
	// Held to what the executor will fork, and here rather than at the loader
	// alone: a value above it renders a config.toml the daemons then refuse,
	// which is a host with no broker where the answer is one number.
	if r.opts.CommandConcurrency > config.MaxConcurrentRuns {
		return fmt.Errorf("--command-concurrency %d is above the %d the executor forks at once, so the "+
			"surplus is refused by the executor after the run is recorded as started. Name %d "+
			"or fewer",
			r.opts.CommandConcurrency, config.MaxConcurrentRuns, config.MaxConcurrentRuns)
	}
	// The same bound from the other side, and negative rather than below 1:
	// zero is the unset signal every tunable shares, so applyDefaults turns it
	// into the default and a caller that builds Options directly leaves it there.
	// Refusing zero here would refuse every such caller for a value nobody typed.
	//
	// A negative one panics the broker as it sizes its slot channel, so the
	// loader refuses it and the config is never written. That arrives as a parse
	// error about a file the operator did not type, after preflight has already
	// passed; named here it is the flag that is wrong.
	if r.opts.CommandConcurrency < 0 {
		return fmt.Errorf("--command-concurrency %d is negative, and a broker cannot "+
			"size itself to run fewer than no commands at all. Name 1 or more",
			r.opts.CommandConcurrency)
	}
	r.warnLongSudoTimeout()
	// Read before an account or a key exists: reporting a typo at the step would
	// leave a half-finished install to re-run.
	if r.opts.KnownHosts != "" {
		if _, _, err := knownhosts.Read(r.opts.KnownHosts); err != nil {
			return fmt.Errorf("--known-hosts: %w", err)
		}
	}
	// An encrypted home is a different directory before its owner logs in, so a
	// write lands in the backing directory and is shadowed the moment it mounts.
	// The config directory answers for the secrets directory and the key too.
	if home := hostlayout.HomeOf(r.layout.ConfigDir); home != "" && hostlayout.LooksEncrypted(home) && !hostlayout.HomeIsMounted(home) {
		return fmt.Errorf("%s is an encrypted home and is not mounted, and %s is inside it: installing now "+
			"writes plaintext to the backing directory. Log in as its owner first",
			home, r.layout.ConfigDir)
	}
	// The config directory is the one faramir creates whose parent can belong to
	// the operator, and ensureDir chowns every ancestor it creates: a ~/.config
	// made that way is root-owned and breaks every other tool that keeps state
	// there.
	if parent := filepath.Dir(r.layout.ConfigDir); !hostfs.Exists(parent) {
		return fmt.Errorf("%s does not exist, and %s is inside it. Create it with "+
			"the ownership you want first: creating it here would hand it to root",
			parent, r.layout.ConfigDir)
	}
	if err := r.refuseRepoint(); err != nil {
		return err
	}
	if err := r.refuseSymlinks(); err != nil {
		return err
	}
	// The binaries are built ahead of time. Checked here rather than at the
	// install step, which is after the accounts and the age key exist.
	if r.binaries == "" {
		return errors.New("cannot find the directory this faramir was run from")
	}
	var missing []string
	for _, name := range installedBinaries {
		if !hostfs.Exists(filepath.Join(r.binaries, name)) {
			missing = append(missing, name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("not built in %s: %s. Run 'make build', then run the "+
			"faramir it built", r.binaries, strings.Join(missing, ", "))
	}
	return nil
}

// refuseRepoint stops a run that would point this host's daemons at a different
// config directory, unless it was asked to.
//
// There is one set of units, with fixed names, so naming a second directory
// repoints the daemons and leaves the first directory where it stands: the refs
// it held leave the value set, so a brokered command that prints one of those
// values prints it, while its age key and ciphertext stay on disk. doctor
// examines only the install the units name.
//
// A flag-less re-run never reaches this: init resolves the config directory
// from the running broker and then from the unit.
func (r *runner) refuseRepoint() error {
	installed := hostunit.ConfigDir(hostunit.BrokerUnit)
	if installed == "" || installed == r.layout.ConfigDir {
		return nil
	}
	if !r.opts.RepointConfig {
		// A dry run reports and writes nothing, so this is what it has to report:
		// refusing here would mean consenting to the change to preview it.
		if r.opts.DryRun {
			r.warnf("this host's daemons load %s, and this run names %s. A real run would be refused: "+
				"pass --repoint-config to point them at the new one, or leave --config-dir out",
				installed, r.layout.ConfigDir)
			return nil
		}
		return fmt.Errorf("this host's daemons load %s, and this run names %s.\nThere is one set of units, "+
			"so the daemons would move and %s would be left holding its age key and its "+
			"ciphertext, no longer redacted.\nPass --repoint-config to point them at the new "+
			"one, then retire %s "+
			"yourself. To provision the install this host has, leave --config-dir out",
			installed, r.layout.ConfigDir, installed, installed)
	}
	// Consented to, and still worth naming: nothing moved, and what is left
	// behind is key material
	// and every value it opens. Said once, here, and by nothing afterwards: the
	// old directory is not part of the install any more, so no later command
	// looks at it. That is the reason to name the files and the commands rather
	// than the directory, since this is the only reading the operator gets.
	managed, _ := filepath.Glob(filepath.Join(installed, "secrets", "*.sops.yml"))
	key := filepath.Join(installed, "age.key")
	store := filepath.Join(installed, "secrets")
	width := max(len(key), len(store))
	r.warnf("the daemons now load %s; %s is no longer part of this install and "+
		"nothing left in it is redacted:\n"+
		"  %-*s  the key that opens what is beside it\n"+
		"  %-*s  %d managed file(s)\n"+
		"Re-encrypt what you still need where the daemons now look, check it with "+
		"`faramir refs`, then remove the old directory:\n"+
		"  sudo rm -rf %s",
		r.layout.ConfigDir, installed,
		width, key, width, store, len(managed), installed)
	return nil
}

// stepPreconditions raises, before anything is handed over, every refusal a
// later step would raise once it was too late to re-run cleanly. It reports
// nothing when it passes, these being preconditions rather than work.
func (r *runner) stepPreconditions() error {
	// Asked whether or not this is a dry run: a dry run must not answer "this
	// would work" about a home where it would not. editedFile reports nothing it
	// cannot read unprivileged, so what a dry run cannot see it does not claim.
	if err := r.refuseUnwritableAgentFiles(); err != nil {
		return err
	}
	if r.opts.DryRun {
		return nil
	}
	if err := r.refuseUnadoptableSSHKey(); err != nil {
		return err
	}
	return r.refuseInvalidSudoers()
}

// refuseUnwritableAgentFiles asks the question stepAgentConfig asks of every
// file it edits, before anything has been handed to an account: failing there
// leaves a host whose units are installed and whose daemons have been reloaded.
// The targets are resolved here and kept, so the question and the writing agree
// on which agents this run is about.
func (r *runner) refuseUnwritableAgentFiles() error {
	targets, err := agentcfg.Resolve(r.opts.Agents, agentcfg.ScopeHome, r.operatorHome, r.operatorHome)
	if err != nil {
		return err
	}
	r.agentTargets = targets
	paths := agentcfg.HomeEditedPaths(targets)
	refused := agentcfg.RefuseUnwritable(r.fs, r.operatorHome, r.operatorUID, "", paths)
	// And the directories those files sit in, which stepAgentConfig creates when
	// they are missing. The home's own question, not the tree's: a symlinked
	// component there is the operator's dotfiles, and agentcfg.WriteFiles reads
	// through it on purpose. 0700 is the mode it makes them with.
	refused = append(refused, hostfs.RefuseUncreatableDirs(
		r.operatorHome, 0o700, r.operatorUID, r.operatorGID, paths)...)
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// refuseUnadoptableSSHKey asks the question stepSSHKey asks, at a point where
// the answer costs nothing. Only for a key already on disk: one this run mints
// is adopted by whoever it is minted for.
func (r *runner) refuseUnadoptableSSHKey() error {
	if !hostfs.Exists(r.layout.SSHKey) {
		return nil
	}
	return r.checkSSHKey(r.layout.SSHKey, r.brokerUID, r.brokerGID)
}

// refuseInvalidSudoers has visudo judge the grant before the run reaches the
// step that installs it. Rendered to a file of its own rather than into
// sudoers.d, which sudo reads. Nothing here is the operator's text, so what
// this catches is a sudo too old for a directive.
func (r *runner) refuseInvalidSudoers() error {
	// The same two directories stepSudoGrant needs: gating on sudoers.d alone
	// would fail the install over a grant that step skips with a warning.
	if !r.layout.AllowSudo || !hostfs.Exists(hostlayout.SudoersDir) || !hostfs.Exists(hostlayout.PamDir) {
		return nil
	}
	visudo, err := exec.LookPath("visudo")
	if err != nil {
		return nil
	}
	body, err := agentcfg.Render("etc/sudoers.tmpl", r.layout)
	if err != nil {
		return err
	}
	dir, err := os.MkdirTemp("", "faramir-sudoers")
	if err != nil {
		return err
	}
	defer func() { _ = os.RemoveAll(dir) }()
	candidate := filepath.Join(dir, "faramir")
	// 0600, not the 0440 the installed file gets: nothing reads this but the
	// visudo below, which parses a file at any mode. The mode sudo requires is
	// asserted where the real file is written.
	if err := os.WriteFile(candidate, body, 0o600); err != nil {
		return err
	}
	if out, checkErr := exec.CommandContext(context.Background(), visudo, "-cf", candidate).
		CombinedOutput(); checkErr != nil {
		return fmt.Errorf("visudo rejects the grant --allow-sudo would install, so "+
			"nothing was written: %w: %s%s", checkErr, strings.TrimSpace(string(out)),
			hostsudo.VersionNote(visudo))
	}
	return nil
}

// refuseSymlinks fails the run when any path this install asserts a mode or an
// owner on is a symlink. Those assertions are what keep the file out of the
// agent's reach, and applying one through a link applies it to the target
// instead.
//
// A precondition rather than a refusal at each step, so the answer is one
// message with the host untouched. It does not replace the O_NOFOLLOW repair
// in ensureOwnership: nothing stops the path being re-pointed after this runs,
// so what it provides is the diagnosis rather than the enforcement.
func (r *runner) refuseSymlinks() error {
	secretsDir := r.layout.SecretsDir()
	// The directories before what is in them, so a linked directory is named as
	// itself rather than through the entries it lists.
	paths := []string{
		r.layout.ConfigDir,
		secretsDir,
		r.layout.SopsConfigPath(),
		r.layout.AgeKeyPath,
		r.layout.LogDir,
		r.layout.AuditLogPath(),
	}
	for _, dir := range []string{secretsDir} {
		// Absent, or a dry run that cannot look inside; either way there is nothing
		// here to answer for.
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, entry := range entries {
			paths = append(paths, filepath.Join(dir, entry.Name()))
		}
	}
	for _, path := range paths {
		info, err := os.Lstat(path)
		if err != nil || info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		target, _ := os.Readlink(path)
		return fmt.Errorf("%s is a symlink to %s, and faramir asserts the mode and owner of that path, which "+
			"through a link would land on the target: nothing has been installed. Replace it "+
			"with a real file or directory, or move the install with --config-dir",
			path, target)
	}
	return nil
}
