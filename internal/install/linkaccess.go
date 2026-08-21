package install

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/sharetree"
)

// linkFile is one linked file that is there, with the stat the grant reads.
type linkFile struct {
	path string
	info os.FileInfo
}

// inspectLinks asks of every entry the questions that can refuse this step, and
// alters nothing: which files are there, and whether any is a symlink, whose
// grant would land on whatever it points at rather than on the file named.
//
// Separate from the loop that grants, so a refusal arrives before the first
// file has been regrouped rather than between two of them. An absent file is
// not a refusal: a link naming nothing is a credential that has left the
// machine, or a home not mounted yet, and the broker reports it per request.
func inspectLinks(links []config.Link) (present []linkFile, absent []string, err error) {
	for _, link := range links {
		info, statErr := os.Lstat(link.Path)
		if statErr != nil {
			if os.IsNotExist(statErr) {
				absent = append(absent, link.Path)
				continue
			}
			return nil, nil, fmt.Errorf("%s: %w", link.Path, statErr)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, nil, fmt.Errorf("%s is a symlink, so the mode and group "+
				"granted here would land on whatever it points at. Name that file "+
				"in the link instead", link.Path)
		}
		present = append(present, linkFile{path: link.Path, info: info})
	}
	return present, absent, nil
}

// stepLinkAccess makes each [[secret.link]] file readable by the account that
// reads it, and by nothing else.
//
// Modes and ownership, never an ACL: a stacked filesystem does not carry one.
// An eCryptfs home takes `setfacl` without error and reads the entry back from
// its own cache, so a grant made that way looks applied, cannot be removed, and
// is not what decides the read.
//
// Two grants per link:
//
//   - The file becomes the broker's own group and group-readable. That group
//     holds one account, for the reason the secrets directory is in a group
//     holding only the keeper: naming a value is not permission to read the file
//     it came from.
//   - The directories above it become the client group, execute only, which is
//     what sharetree grants for an enrolled tree. Traversal is not read.
//
// The owner is left alone: the file is the operator's and their tool rewrites
// it. Neither grant survives a tool that writes a temp file and renames over
// it, the replacement being created 0600; an ACL is lost the same way.
// `faramir doctor` asks the broker's own account whether it can still read each
// file.
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

	// Every file judged before the first one is granted: a refusal raised part
	// way through the loop leaves the links before it regrouped and the
	// directories above them opened, for a run that then stopped. One link the
	// operator cannot use is not a reason to have altered the others.
	present, absent, err := inspectLinks(links)
	if err != nil {
		return err
	}

	granted := 0
	for _, file := range present {
		path, info := file.path, file.info
		// The file, not its directory: Reachable leaves the last component of the
		// path it is given alone, so naming the directory stops one hop short and
		// leaves the one holding the file unenterable.
		result, err := sharetree.Reachable(sharetree.Options{
			Dir: path, Operator: r.opts.AgentUser,
			Group: r.layout.ClientGroup,
		})
		if err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
		granted += result.Changed

		// The owner's own bits as they are, group read, and nothing for anybody
		// else: a file the operator keeps at 0400 stays unwritable by them.
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
		// Named rather than counted: which file is missing says whether this is a
		// credential that has gone or a home that is not mounted.
		detail += fmt.Sprintf("; %d not there yet: %s",
			len(absent), strings.Join(absent, ", "))
	}
	r.step("linked files", granted > 0, detail)
	return nil
}

// LinkSteps is what an install run does about a link and nothing else: write
// the config that names it, grant the access it needs, and re-render the deny
// rules that refuse its file. `faramir link` applies these rather than a whole
// install. stepPreconditions is not optional here: it resolves the agents
// whose files stepAgentConfig writes, so a list without it writes no deny
// rule.
func (r *runner) LinkSteps() []namedStep {
	return []namedStep{
		{labelResolveIDs, r.resolveIDs},
		{labelPreconditions, r.stepPreconditions},
		{labelConfig, r.stepConfig},
		{"linked files", r.stepLinkAccess},
		{labelAgentConfig, r.stepAgentConfig},
	}
}

// keepInstalledGrant takes the sudo arrangement off the installed config so
// that rewriting config.toml does not remove it. `init` does the opposite,
// --allow-sudo being a switch a re-run without takes away; adding a link is not
// a request to change that, and stepConfig renders the whole file from the
// layout, so without this a `link add` would drop [escalation] and leave the
// sudoers entry pointing at a broker that no longer names it.
func keepInstalledGrant(opts *Options, configDir string) error {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return err
	}
	opts.AllowSudo = cfg.Escalation.ExecUser != ""
	opts.NotifyCommand = cfg.Escalation.NotifyCommand
	return nil
}

// AddLink adds one entry and applies everything that follows from it.
//
// The order is the point. The grant comes before the probe, the question being
// whether the broker can read the file; the probe comes before the entry is
// written, a selector that names nothing otherwise leaving the broker refusing
// every command. A probe that fails puts the grant back: a file the broker can
// read but is not told about is a widening with nothing to show for it.
//
// An entry this install already carries, spelled the same way, is not an error:
// it is re-applied by reassertLink and the bool comes back false. A ref it
// carries against a different file, type or key is, a ref having one
// definition. The two are not the same request, and answering the second one by
// replacing the entry would change which credential every caller of that name
// receives, silently.
func AddLink(opts Options, link config.Link) (Report, bool, error) {
	if err := config.ValidateLink(link); err != nil {
		return Report{}, false, err
	}
	configFile := filepath.Join(configDirOr(opts.ConfigDir), "config.toml")
	existing, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", configFile, err)
	}
	if other, claimed := linkNamed(existing, link.Ref); claimed {
		if other != link {
			return Report{}, false, redefinedRef(configFile, other, link)
		}
		report, err := reassertLink(opts, existing, link)
		return report, false, err
	}
	// Refused rather than recorded: a link nothing could verify may refuse every
	// brokered command later, at a moment nobody chose.
	if _, err := os.Stat(link.Path); err != nil {
		return Report{}, false, fmt.Errorf("%s: %w\nA link is checked when it is added, so "+
			"the file has to be there. If this is an encrypted home, mount it first",
			link.Path, err)
	}
	// What the file itself answers, asked before anything is altered: the wrong
	// --type, or a --key naming nothing, is a link that was never going to work,
	// and finding that out after the grant leaves a credential file regrouped and
	// the directories above it opened up for it. Root reads what the broker
	// cannot, so this is not the probe below: this says the content yields a
	// value, and probeLink says the broker can reach it.
	if _, err := secretlink.Read(link.Path, link.Type, link.Key); err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", link.Path,
			secretlink.Refusal(link.Path, link.Type, err))
	}

	opts.links, opts.linksSet = append(append([]config.Link{}, existing...), link), true
	if err := keepInstalledGrant(&opts, configDirOr(opts.ConfigDir)); err != nil {
		return Report{}, false, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, false, err
	}
	if err := run.resolveIDs(); err != nil {
		return Report{}, false, err
	}

	restore, err := run.grantOne(link)
	if err != nil {
		return Report{}, false, err
	}
	// Put back on any failure from here on, not only the probe's: the file has
	// been regrouped and the entry has not been written, so a run that stops in
	// between leaves a credential file readable by the broker that nothing told
	// it about.
	if err := run.probeLink(link); err != nil {
		return Report{}, false, revert(restore, err)
	}
	report, err := run.apply(run.LinkSteps())
	if err != nil {
		return report, false, revert(restore, err)
	}
	return report, true, nil
}

// linkNamed is the entry claiming a ref, and whether one does.
func linkNamed(existing []config.Link, ref string) (config.Link, bool) {
	for _, link := range existing {
		if link.Ref == ref {
			return link, true
		}
	}
	return config.Link{}, false
}

// redefinedRef is one ref asked to name two different files, types or keys. It
// names both sides: which credential a caller of that name receives is the
// whole of what differs between them, and neither side is visible from the ref.
func redefinedRef(configFile string, other, link config.Link) error {
	return fmt.Errorf("%s already names %s, as %s (%s%s), and this asks for %s (%s%s). "+
		"A ref has one definition, and a caller naming it cannot tell which file "+
		"answered: remove that one with `faramir link rm %s` first, or choose another "+
		"name", configFile, link.Ref, other.Path, other.Type, keySuffix(other.Key),
		link.Path, link.Type, keySuffix(link.Key), link.Ref)
}

// keySuffix is a link's selector for a message that has already named its type,
// and nothing at all for the two types that select nothing.
func keySuffix(key string) string {
	if key == "" {
		return ""
	}
	return " " + key
}

// reassertLink re-applies an entry the config already carries: the grant, the
// deny rules and the config are rendered again, so a grant a tool took away by
// renaming its own file comes back, and so does a rule an agent's settings
// dropped. Nothing is written that was not there, so an untouched host reports
// no change and the caller skips the reload.
//
// The order AddLink keeps is not this one's to keep. Nothing here can leave a
// file regrouped for an entry that was never written, the entry being written
// already, so the steps grant and the probe asks afterwards whether the broker
// can read what it was granted. There is nothing to put back on a failure
// either: the grant belongs to an entry that stands whatever this run does.
func reassertLink(opts Options, existing []config.Link, link config.Link) (Report, error) {
	opts.links, opts.linksSet = existing, true
	if err := keepInstalledGrant(&opts, configDirOr(opts.ConfigDir)); err != nil {
		return Report{}, err
	}
	run, err := newRunner(opts)
	if err != nil {
		return Report{}, err
	}
	report, err := run.apply(run.LinkSteps())
	if err != nil {
		return report, err
	}
	if _, statErr := os.Stat(link.Path); statErr == nil {
		return report, run.probeLink(link)
	}
	// A file that is gone is the case the broker treats as an entry naming
	// nothing rather than as an error, the credential having left the machine.
	// Refusing here would fail a converge run over a home that is not mounted,
	// so it is said and the probe is skipped: there is nothing to read.
	report.Warnings = append(report.Warnings, fmt.Sprintf(
		"%s: %s is not there, so nothing was granted or read. The entry stands "+
			"and the broker treats it as a ref naming nothing", link.Ref, link.Path))
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

// RemoveLink drops one entry and re-renders what named it. It does not narrow
// the file again: it does not know the mode that file had before the grant, so
// the caller is told what the file is now and what would narrow it. Removing
// the entry is what takes the value out of the redactor.
//
// A ref this install does not carry is not an error, for the reason a second
// add is not: what is asked for is the state the host is already in. The
// returned entry is the zero value there, which is how the caller tells the two
// apart.
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
	// kept is existing where nothing matched, so the steps below re-render what
	// is already there and report no change.
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

// Links is what the install declares, for `faramir link ls`.
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

	// The file, not its directory: Reachable grants every directory above the
	// path it is given and leaves the last component alone, so naming the
	// directory would stop one hop short and leave the one holding the file
	// unenterable. The file itself is granted below.
	if _, err := sharetree.Reachable(sharetree.Options{
		Dir: link.Path, Operator: r.opts.AgentUser,
		Group: r.layout.ClientGroup,
	}); err != nil {
		return nil, fmt.Errorf("%s: %w", link.Path, err)
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
// value out of it, by being that account: root can read anything and would
// answer yes to a file the broker cannot open.
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
// the broker can read each linked file, and the executor cannot. Asked as
// those accounts rather than worked out from the mode, which is what catches a
// tool having replaced its own file and taken the group with it.
//
// A file that is not there is neither answer: the credential has left the
// machine, or the home holding it is not mounted.
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
