package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/sharetree"
)

// stepLinkAccess makes each [[secret.link]] file readable by the account that
// reads it, and by nothing else.
//
// **Modes and ownership, never an ACL**, and not as a preference: a stacked
// filesystem does not carry one.  An eCryptfs home takes `setfacl` without
// error and reads the entry back from its own cache, so a grant made that way
// looks applied, cannot be removed, and is not what decides the read.
// Ownership and modes belong to the lower filesystem and hold everywhere.
//
// Two grants per link, each a shape this install already uses:
//
//   - The file becomes the broker's own group and group-readable.  That group
//     holds one account, which is the reasoning that puts the secrets directory
//     in a group holding only the keeper: naming a value is not permission to
//     read the file it came from, so the executor must not be in it.
//   - The directories above it become the client group, execute only, which is
//     what sharetree grants for an enrolled tree.  Traversal is not read: the
//     file's own mode still refuses every account but the broker's.
//
// The owner is left alone.  The file is the operator's and their tool rewrites
// it, so taking it over would be taking it away from the thing that maintains
// it, and a rewrite would hand it straight back.
//
// Neither grant survives a tool that writes a temp file and renames over it:
// the replacement is created fresh, and its 0600 creation mode leaves nothing
// for a group to read.  An ACL is lost the same way, its inherited entry masked
// to nothing by that same mode, so this is not a cost of choosing modes.  What
// catches it is `faramir doctor`, which asks the broker's own account whether it
// can still read each file.
func (r *runner) stepLinkAccess() error {
	links := r.opts.links
	if len(links) == 0 {
		r.skip("linked files", "no [[secret.link]] entries are configured")
		return nil
	}
	if r.opts.DryRun {
		r.skip("linked files", "dry run")
		return nil
	}

	granted, absent := 0, []string{}
	for _, link := range links {
		path := link.Path
		info, err := os.Lstat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// Not a failure: a link naming nothing is a credential that has left
				// the machine, or a home not mounted yet, and the broker reports it
				// per request rather than the install refusing to finish over it.
				absent = append(absent, path)
				continue
			}
			return fmt.Errorf("%s: %w", path, err)
		}
		// Before the directories: a symlink here would send the grant to whatever
		// it points at, and ensureOwnership refuses one, so the refusal should
		// arrive before anything above it has been regrouped.
		if info.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%s is a symlink, so the mode and group granted here "+
				"would land on whatever it points at. Name that file in the link "+
				"instead", path)
		}

		result, err := sharetree.Reachable(sharetree.Options{
			Dir: filepath.Dir(path), Operator: r.opts.AgentUser,
			Group: r.layout.ClientGroup,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", filepath.Dir(path), err)
		}
		granted += result.Changed

		// The owner's own bits as they are, group read, and nothing for anybody
		// else.  Widening only what the broker needs: a file the operator keeps at
		// 0400 stays unwritable by them.
		mode := (info.Mode().Perm() & 0o700) | 0o040
		changed, err := r.fs.ensureOwnership(path, mode, keep, r.brokerGID)
		if err != nil {
			return err
		}
		if changed {
			granted++
		}
	}

	detail := fmt.Sprintf("%d linked file(s) readable by %s",
		len(links)-len(absent), r.layout.BrokerUser)
	if len(absent) > 0 {
		// Named rather than counted: which file is missing is what says whether
		// this is a credential that has gone or a home that is not mounted.
		detail += fmt.Sprintf("; %d not there yet: %s",
			len(absent), strings.Join(absent, ", "))
	}
	r.step("linked files", granted > 0, detail)
	return nil
}

// LinkSteps is what an install run does about a link and nothing else: write
// the config that names it, grant the access it needs, and re-render the deny
// rules that refuse its file.  `faramir link` applies these rather than a whole
// install, so adding a link does not reinstall the binary or rewrite the units.
// stepPreconditions is not optional here even though nothing in it is about
// links: it is what resolves the agents whose files stepAgentConfig writes, so
// a list without it writes no deny rule at all and says it found no agent.
func (r *runner) LinkSteps() []namedStep {
	return []namedStep{
		{"resolveIDs", r.resolveIDs},
		{"preconditions", r.stepPreconditions},
		{"config", r.stepConfig},
		{"linked files", r.stepLinkAccess},
		{"agent config", r.stepAgentConfig},
	}
}

// keepInstalledGrant takes the sudo arrangement off the installed config so
// that rewriting config.toml does not remove it.
//
// `init` deliberately does the opposite: --allow-sudo is a switch, and a re-run
// without it takes the grant away, which is the direction that reduces reach.
// Adding a link is not a request to change any of that, and stepConfig renders
// the whole file from the layout, so without this a `link add` on a host
// installed with --allow-sudo would silently drop [approval] and leave the sudoers
// entry and PAM service pointing at a broker that no longer names them.
func keepInstalledGrant(opts *Options, configDir string) error {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return err
	}
	opts.AllowSudo = cfg.Approval.ExecUser != ""
	opts.NotifyCommand = cfg.Approval.NotifyCommand
	return nil
}

// AddLink adds one entry and applies everything that follows from it.
//
// The order is the point.  The grant comes before the probe, because the
// question is whether the *broker* can read the file and it cannot until it has
// been granted; the probe comes before the entry is written, because a selector
// that names nothing would otherwise leave the broker refusing every command
// until somebody noticed.  A probe that fails puts the grant back: a file the
// broker can read but is not told about is a widening with nothing to show for
// it.
func AddLink(opts Options, link config.Link) (Report, error) {
	if err := config.ValidateLink(link); err != nil {
		return Report{}, err
	}
	configFile := filepath.Join(configDirOr(opts.ConfigDir), "config.toml")
	existing, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, fmt.Errorf("%s: %w", configFile, err)
	}
	for _, other := range existing {
		if other.Ref == link.Ref {
			return Report{}, fmt.Errorf("%s already names %s, at %s. A ref has one "+
				"definition; remove that one first, or choose another name",
				configFile, link.Ref, other.Path)
		}
	}
	// Refused rather than recorded.  The probe is what this command is for, and a
	// link nothing could verify is one that may refuse every brokered command
	// later, at a moment nobody chose.
	if _, err := os.Stat(link.Path); err != nil {
		return Report{}, fmt.Errorf("%s: %w\nA link is checked when it is added, so "+
			"the file has to be there. If this is an encrypted home, mount it first",
			link.Path, err)
	}

	opts.links, opts.linksSet = append(append([]config.Link{}, existing...), link), true
	if err := keepInstalledGrant(&opts, configDirOr(opts.ConfigDir)); err != nil {
		return Report{}, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, err
	}
	if err := run.resolveIDs(); err != nil {
		return Report{}, err
	}

	restore, err := run.grantOne(link)
	if err != nil {
		return Report{}, err
	}
	// Put back on any failure from here on, not only the probe's.  The file has
	// been regrouped and the entry has not been written, so a run that stops
	// anywhere in between leaves exactly what the rollback exists to prevent:
	// a credential file readable by the broker that nothing told it about.
	if err := run.probeLink(link); err != nil {
		return Report{}, revert(restore, err)
	}
	report, err := run.apply(run.LinkSteps())
	if err != nil {
		return report, revert(restore, err)
	}
	return report, nil
}

// revert undoes the grant and reports both failures when the undo fails too.
func revert(restore func() error, cause error) error {
	if err := restore(); err != nil {
		return fmt.Errorf("%w\nand the access granted for the probe could not be "+
			"put back, so %v", cause, err)
	}
	return cause
}

// RemoveLink drops one entry and re-renders what named it.
//
// What it does not do is narrow the file again.  It does not know the mode that
// file had before the grant, and guessing would be as likely to break the tool
// that owns it as to tidy anything; the caller is told what the file is now and
// what would narrow it.  Removing the entry is what takes the value out of the
// redactor, which is the part that had to be exact.
func RemoveLink(opts Options, ref string) (Report, config.Link, error) {
	configFile := filepath.Join(configDirOr(opts.ConfigDir), "config.toml")
	existing, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, config.Link{}, fmt.Errorf("%s: %w", configFile, err)
	}
	kept := make([]config.Link, 0, len(existing))
	var removed config.Link
	for _, link := range existing {
		if link.Ref == ref {
			removed = link
			continue
		}
		kept = append(kept, link)
	}
	if removed.Ref == "" {
		return Report{}, config.Link{}, fmt.Errorf("%s names no link %q; `faramir link ls` "+
			"lists the ones it does", configFile, ref)
	}

	opts.links, opts.linksSet = kept, true
	if err := keepInstalledGrant(&opts, configDirOr(opts.ConfigDir)); err != nil {
		return Report{}, config.Link{}, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, config.Link{}, err
	}
	report, err := run.apply(run.LinkSteps())
	return report, removed, err
}

// Links is what the install declares, for `faramir link ls`.  The base file
// alone, which is the set this command owns.
func Links(configDir string) ([]config.Link, error) {
	return config.BaseLinks(filepath.Join(configDirOr(configDir), "config.toml"))
}

func configDirOr(dir string) string {
	if dir == "" {
		return DefaultConfigDir
	}
	return dir
}

// grantOne applies the file half of the grant and returns what puts it back.
// The directories above it are not restored: they are shared with the traversal
// an enrolled tree needs, and narrowing one could take away access this command
// never gave.
func (r *runner) grantOne(link config.Link) (func() error, error) {
	info, err := os.Lstat(link.Path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return nil, fmt.Errorf("%s is a symlink, so the mode and group granted here "+
			"would land on whatever it points at. Name that file in the link instead",
			link.Path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil, fmt.Errorf("%s: cannot read ownership", link.Path)
	}
	was, wasGID := info.Mode().Perm(), int(stat.Gid)

	if _, err := sharetree.Reachable(sharetree.Options{
		Dir: filepath.Dir(link.Path), Operator: r.opts.AgentUser,
		Group: r.layout.ClientGroup,
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Dir(link.Path), err)
	}
	mode := (info.Mode().Perm() & 0o700) | 0o040
	if _, err := r.fs.ensureOwnership(link.Path, mode, keep, r.brokerGID); err != nil {
		return nil, err
	}
	return func() error {
		_, err := r.fs.ensureOwnership(link.Path, was, keep, wasGID)
		return err
	}, nil
}

// probeLink asks whether the broker's own account can read the file and get a
// value out of it, by being that account.  Root can read anything and would
// answer yes to a file the broker cannot open, which is the failure this exists
// to catch.
func (r *runner) probeLink(link config.Link) error {
	args := []string{selfPath(), "read-link", "--path", link.Path, "--type", link.Type}
	if link.Key != "" {
		args = append(args, "--key", link.Key)
	}
	out, err := asUser(r.layout.BrokerUser, args...)
	if err == nil {
		return nil
	}
	// The child's own message, which names the file and never quotes it.
	detail := strings.TrimSpace(out)
	if detail == "" {
		detail = err.Error()
	}
	return fmt.Errorf("%s cannot read %s as %s: %s",
		r.layout.BrokerUser, link.Ref, link.Path, detail)
}

// diagnoseLinkedAccess asks the two questions the grant exists to make true:
// the broker can read each linked file, and the executor cannot.
//
// Asked as those accounts rather than worked out from the mode, which is what
// makes it worth running: it is the one check that catches a tool having
// replaced its own file, taking the group with it, and it answers the same way
// whatever mechanism granted the access and whatever filesystem the home is.
//
// A file that is not there is neither answer.  The credential has left the
// machine, or the home holding it is not mounted, and both are reported by the
// broker per request.
func diagnoseLinkedAccess(report *DoctorReport, opts DoctorOptions, cfg *config.Config) {
	const name = "linked file access"
	if len(cfg.Secret.Links) == 0 {
		report.addf(name, StatusOK, "no [[secret.link]] entries are configured")
		return
	}
	accounts, skipped := askable(opts.BrokerUser, opts.ExecUser)
	if skipped || len(accounts) < 2 {
		report.unaskedf(name, len(cfg.Secret.Links), "the broker and executor "+
			"accounts are not both named, so whether the %d linked file(s) are "+
			"readable was not asked", len(cfg.Secret.Links))
		return
	}

	var unreadable, reachable, absent []string
	for _, link := range cfg.Secret.Links {
		switch {
		case !exists(link.Path):
			absent = append(absent, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		case !canRead(opts.BrokerUser, link.Path):
			unreadable = append(unreadable, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		case canRead(opts.ExecUser, link.Path):
			reachable = append(reachable, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		}
	}

	switch {
	case len(reachable) > 0:
		report.addf(name, StatusFailed, "%s can read a linked file directly, so a "+
			"brokered command reaches the plaintext without asking for the ref and "+
			"without the redactor seeing it: %s", opts.ExecUser,
			strings.Join(reachable, ", "))
	case len(unreadable) > 0:
		report.addf(name, StatusFailed, "%s cannot read a linked file, so its value "+
			"is absent from the redactor and every brokered command is refused. A "+
			"tool that replaces its own file rather than rewriting it takes the group "+
			"with it; `faramir init` grants it again: %s", opts.BrokerUser,
			strings.Join(unreadable, ", "))
	case len(absent) > 0:
		report.addf(name, StatusWarn, "%d linked file(s) are readable by %s alone; "+
			"%d not there, which is a credential removed or a home not mounted: %s",
			len(cfg.Secret.Links)-len(absent), opts.BrokerUser, len(absent),
			strings.Join(absent, ", "))
	default:
		report.addf(name, StatusOK, "%d linked file(s) readable by %s and not by %s",
			len(cfg.Secret.Links), opts.BrokerUser, opts.ExecUser)
	}
}
