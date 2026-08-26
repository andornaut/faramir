package install

import (
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/fserr"
	"github.com/andornaut/faramir/internal/secretlink"
	"github.com/andornaut/faramir/internal/sharetree"
)

// linkFault is why one linked file is not usable as it stands, phrased as what
// has to change. Empty when it is.
//
// Read off the file's own ownership and mode rather than by asking the account:
// this states the arrangement a link needs (the broker's group, group read, and
// nothing for anybody else) in the terms whoever manages the host's permissions
// sets it in. `faramir doctor` asks the accounts themselves, which is the check
// that catches what a mode does not show.
func (r *runner) linkFault(link config.Link) (string, error) {
	info, err := os.Lstat(link.Path)
	if err != nil {
		return "", err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Sprintf("%s is a symlink, and a link names the file that holds "+
			"the value: name what it points at instead", link.Path), nil
	}
	// A directory above it answers for the file whatever the file's own bits say,
	// so it is asked first.
	//
	// Asked about the broker rather than about the client group, this being the
	// one account that has to get there: it is in more than one group, and a
	// directory the operator opened to another of them is one it can already
	// enter. The client group is still what a remedy names.
	blocked, err := sharetree.Traversable(sharetree.Options{
		Dir: link.Path, Operator: r.opts.AgentUser, Group: r.layout.ClientGroup,
		Account: r.layout.BrokerUser,
	})
	if err != nil {
		return "", err
	}
	if len(blocked) > 0 {
		return fmt.Sprintf("%s cannot reach %s (%s): it cannot enter %s. Open "+
			"them:\n%s", r.layout.BrokerUser, config.Shown(link.Path), config.Shown(link.Ref),
			sharetree.Describe(blocked),
			sharetree.Fix(blocked, r.layout.ClientGroup)), nil
	}

	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("%s: cannot read ownership", link.Path)
	}
	mode := info.Mode().Perm()
	var fix []string
	if int(stat.Gid) != r.brokerGID {
		fix = append(fix, fmt.Sprintf("sudo chgrp %s %s", r.brokerGroupName(), link.Path))
	}
	if mode&0o040 == 0 {
		fix = append(fix, "sudo chmod g+r "+link.Path)
	}
	// Not only the executor: group read for the broker is the whole grant, and
	// anything other can read every account on the host can read.
	if mode&0o004 != 0 {
		fix = append(fix, "sudo chmod o-r "+link.Path)
	}
	if len(fix) == 0 {
		return "", nil
	}
	return fmt.Sprintf("%s (%s) is %s %04o, and a linked file has to be group %s and group-readable, and "+
		"readable by nobody else:\n%s",
		config.Shown(link.Path), config.Shown(link.Ref), fileGroup(info), mode, r.brokerGroupName(),
		strings.Join(fix, " && ")), nil
}

// groupNameOf is an account's own group, by name, for a remedy a reader pastes
// into a shell: an account adopted by --broker-user may have a group named
// something else, and a chgrp naming the account fails with "invalid group".
// Falls back to the account name, so the remedy is never printed with an empty
// field.
func groupNameOf(account string) string {
	if _, name, err := primaryGroup(account); err == nil {
		return name
	}
	return account
}

// fileGroup is the group that owns a file, by name where the group still
// exists.
func fileGroup(info os.FileInfo) string {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "?"
	}
	gid := strconv.FormatUint(uint64(stat.Gid), 10)
	if group, err := user.LookupGroupId(gid); err == nil {
		return group.Name
	}
	return gid
}

// stepLinkAccess checks that every [[secret.link]] file is readable by the
// account that reads it, and by nothing else. It alters nothing: the file is
// the operator's, and so is every directory above it, and faramir does not
// change the ownership or mode of a path it does not own. What the checks find
// is reported with the command that fixes it, for whoever manages the host's
// permissions to apply.
//
// An absent file is not a fault here: a link naming nothing is a credential
// that has left the machine, or a home not mounted yet, and the broker reports
// it per request.
//
// Every link is asked about before any is reported, so one run names everything
// that has to change rather than one thing per re-run.
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

	var faults, absent []string
	for _, link := range links {
		if !exists(link.Path) {
			absent = append(absent, link.Path)
			continue
		}
		fault, err := r.linkFault(link)
		if err != nil {
			return fmt.Errorf("%s: %w", link.Path, err)
		}
		if fault != "" {
			faults = append(faults, fault)
		}
	}
	if len(faults) > 0 {
		return fmt.Errorf("%d linked file(s) are not usable as they are, and "+
			"faramir does not alter a file it does not own:\n\n%s",
			len(faults), strings.Join(faults, "\n\n"))
	}

	detail := fmt.Sprintf("%d linked file(s) readable by %s",
		len(links)-len(absent), r.layout.BrokerUser)
	if len(absent) > 0 {
		// Named rather than counted: which file is missing says whether this is a
		// credential that has gone or a home that is not mounted.
		detail += fmt.Sprintf("; %d not there: %s",
			len(absent), strings.Join(absent, ", "))
	}
	// Never changed: this step asks questions and alters nothing.
	r.step("linked files", false, detail)
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
		// And into every tree already enrolled, for the reason BlockedSteps gives.
		{labelEnrolledTrees, r.stepEnrolledTrees},
		// A linked path is a subject in the command guard's rules as well as in
		// the agents' own, so both are rendered here.
		{"deny patterns", r.stepDenyPatterns},
	}
}

// keepInstalledGrant takes the sudo arrangement off the installed config so
// that rewriting config.toml does not remove it. `init` does the opposite with
// the grant, --allow-sudo being a switch a re-run without takes away; adding a
// link is not a request to change that, and stepConfig renders the whole file
// from the layout, so without this a `link add` would drop [sudo] and leave the
// sudoers entry pointing at a broker that no longer names it. The notifier is
// read back by `init` as well, under a grant it was given; this names it here
// rather than leaving it to adoption because the grant it hangs off is the one
// being read on this line.
func keepInstalledGrant(opts *Options, configDir string) error {
	cfg, err := config.Load(filepath.Join(configDir, "config.toml"))
	if err != nil {
		return err
	}
	opts.AllowSudo = cfg.Sudo.ExecUser != ""
	opts.NotifyCommand = cfg.Sudo.NotifyCommand
	return nil
}

// AddLink adds one entry and applies everything that follows from it.
//
// The order is the point. Every question is asked before the entry is written,
// and nothing about the file is altered to make an answer come out right: an
// entry naming a file the broker cannot read is a ref that answers nothing, and
// one naming a file the executor can read hands the plaintext to whatever an
// agent asks to run.
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
	if err := recordConfigDigest(&opts, configFile); err != nil {
		return Report{}, false, err
	}
	existing, err := config.BaseLinks(configFile)
	if err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", configFile, err)
	}
	if other, claimed := linkNamed(existing, link.Ref); claimed {
		// The strictness is how the entry is matched rather than what it names, so
		// a re-add that changes it edits the entry instead of colliding with it.
		// In both directions: what a converge names every run is the state it
		// wants, and a --strict left off the list means it was withdrawn.
		tightened := other
		tightened.Strict = link.Strict
		if tightened != link {
			return Report{}, false, redefinedRef(configFile, other, link)
		}
		if other.Strict != link.Strict {
			updated := slices.Clone(existing)
			for i := range updated {
				if updated[i].Ref == link.Ref {
					updated[i].Strict = link.Strict
				}
			}
			report, err := reassertLink(opts, updated, link)
			// Changed: the rules this renders are not the ones the host had.
			return report, err == nil, err
		}
		report, err := reassertLink(opts, existing, link)
		return report, false, err
	}
	// Blocked rather than recorded: a link nothing could verify may refuse every
	// brokered command later, at a moment nobody chose.
	if _, err := os.Stat(link.Path); err != nil {
		return Report{}, false, fmt.Errorf("%w\nA link is checked when it is added, so "+
			"the file has to be there. If this is an encrypted home, mount it first",
			fserr.At(link.Path, err))
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

	if err := run.refuseShadowedRef(configFile, link.Ref); err != nil {
		return Report{}, false, err
	}
	fault, err := run.linkFault(link)
	if err != nil {
		return Report{}, false, fmt.Errorf("%s: %w", link.Path, err)
	}
	if fault != "" {
		return Report{}, false, errors.New(fault)
	}
	// What the broker itself gets out of the file, which canRead does not ask:
	// the account can open it and the selector yields a value.
	if err := run.probeLink(link); err != nil {
		return Report{}, false, err
	}
	report, err := run.apply(run.LinkSteps())
	if err != nil {
		return report, false, err
	}
	return report, true, nil
}

// refuseShadowedRef refuses an entry naming a ref the managed store already
// defines. Asked before the entry is written, because the broker refuses every
// brokered command while one stands: the managed value is what callers get, and
// the linked file then holds a second value for that name which nothing reads
// and nothing redacts.
//
// Asked of the running broker, which is the only thing that can answer it. The
// managed values are encrypted and the keeper alone decrypts them, so the refs
// they define cannot be read out of the config this command is editing.
//
// Asked as the agent account, that being the one the broker's socket admits.
//
// A broker that does not answer refuses the add rather than letting it through
// unasked. The question is not optional: an entry claiming a name the store
// already answers refuses every brokered command on the host from the moment
// the broker next loads, and writing one while nothing could check is how that
// arrives at a moment nobody chose. `refs` answers on a host that has no
// secrets yet and on one whose store will not serve, so there is no first
// install this locks out; what it stops is an add made against a broker that is
// down.
func (r *runner) refuseShadowedRef(configFile, ref string) error {
	if r.opts.DryRun {
		return nil
	}
	cfg, err := config.Load(configFile)
	if err != nil {
		return fmt.Errorf("%s: %w", configFile, err)
	}
	if cfg.Server.SocketPath == "" {
		return fmt.Errorf("%s names no [server] socket_path, so the broker cannot "+
			"be asked whether it already serves %s. Re-run `sudo faramir init` "+
			"before adding a link", configFile, ref)
	}
	out, err := asUser(r.opts.AgentUser, "env",
		"FARAMIR_SOCKET="+cfg.Server.SocketPath, selfPath(), "refs")
	if err != nil {
		return fmt.Errorf("the broker did not answer, so whether it already serves %s could not be asked, "+
			"and an entry claiming a name it serves refuses every brokered command. Start it "+
			"and run this again (`systemctl start faramir-broker.socket`): %w", ref, err)
	}
	for line := range strings.SplitSeq(strings.TrimSpace(out), "\n") {
		if strings.TrimSpace(line) != "faramir://"+ref {
			continue
		}
		return fmt.Errorf("the broker already serves %s, so a [[secret.link]] entry cannot claim that name: "+
			"a ref has one definition. Choose another, or take the value out of the managed "+
			"store with `sudo faramir vault edit` first", ref)
	}
	return nil
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
	return fmt.Errorf("%s already names %s, as %s (%s%s), and this asks for %s (%s%s). A ref has one "+
		"definition: remove that one with `faramir link rm %s`, or choose another name", configFile, link.Ref, other.Path, other.Type, keySuffix(other.Key),
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

// reassertLink re-applies an entry the config already carries: the deny rules
// and the config are rendered again, so a rule an agent's settings dropped
// comes back. Nothing is written that was not there, so an untouched host
// reports no change and the caller skips the reload.
//
// The access the file needs is checked by the steps and not repaired by them.
// A tool that replaced its own file and took the group with it is reported
// here, with the command that puts it back.
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

// RemoveLink drops one entry and re-renders what named it. The file's own group
// and mode are left alone, faramir having not set them: the caller is told what
// the file is now and what would narrow it. Removing the entry is what takes
// the value out of the redactor.
//
// A ref this install does not carry is not an error, for the reason a second
// add is not: what is asked for is the state the host is already in. The
// returned entry is the zero value there, which is how the caller tells the two
// apart.
func RemoveLink(opts Options, ref string) (Report, config.Link, error) {
	configFile := filepath.Join(configDirOr(opts.ConfigDir), "config.toml")
	if err := recordConfigDigest(&opts, configFile); err != nil {
		return Report{}, config.Link{}, err
	}
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
	if dir := blockingDir(r.layout.BrokerUser, link.Path); dir != "" {
		return fmt.Errorf("%s cannot reach %s at %s: it cannot enter %s, so the mode "+
			"on the file decides nothing. Open that directory to the broker, or keep "+
			"the file somewhere it can already reach:\n"+
			"sudo chgrp %s %s && sudo chmod g+x %s",
			r.layout.BrokerUser, link.Ref, link.Path, dir,
			groupNameOf(r.layout.BrokerUser), dir, dir)
	}
	return fmt.Errorf("%s cannot read %s as %s: %s",
		r.layout.BrokerUser, link.Ref, link.Path, detail)
}

// diagnoseLinkedAccess asks the two questions the grant exists to make true:
// the broker can read each linked file, and the executor cannot. Asked as
// those accounts rather than worked out from the mode, which is what catches a
// tool having replaced its own file and taken the group with it.
//
// A file that is not there answers neither, and fails too: the entry names a
// value nothing can produce, whether the credential has left the machine or the
// home holding it is not mounted. Which of the two it is, the operator knows and
// this cannot.
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
	// The question is put by being those accounts, which runuser needs root for.
	// Unprivileged, runuser fails for every path, and reading that as the answer
	// reported the broker unable to open files it was serving values from: a
	// question that cannot be asked is unasked, not a verdict, which is the
	// contract every other boundary check keeps.
	if os.Geteuid() != 0 {
		report.unaskedf(name, len(cfg.Secret.Links), "run doctor as root to ask "+
			"this: whether the %d linked file(s) are readable by %s and not by %s "+
			"is answered by being those accounts", len(cfg.Secret.Links),
			opts.BrokerUser, opts.ExecUser)
		return
	}

	var unreadable, reachable, absent []string
	for _, link := range cfg.Secret.Links {
		switch {
		case !exists(link.Path):
			absent = append(absent, fmt.Sprintf("%s (%s)", link.Ref, link.Path))
		case !canRead(opts.BrokerUser, link.Path):
			entry := fmt.Sprintf("%s (%s)", link.Ref, link.Path)
			// The directory, where that is what refuses: the remedy below is about
			// the file's own group and mode, and neither is the problem here.
			if dir := blockingDir(opts.BrokerUser, link.Path); dir != "" {
				entry += fmt.Sprintf(", which it cannot enter %s to reach", dir)
			}
			unreadable = append(unreadable, entry)
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
		report.addf(name, StatusFailed, "%s cannot read a linked file, so that ref is refused while the plaintext is still "+
			"on disk. A tool that replaces its own file takes the group with it; `sudo chgrp "+
			"%s PATH && sudo chmod g+r PATH` puts it back: %s", opts.BrokerUser, groupNameOf(opts.BrokerUser),
			strings.Join(unreadable, ", "))
	case len(absent) > 0:
		report.addf(name, StatusFailed, "%d linked file(s) are readable by %s alone; %d are not there, so those refs "+
			"answer nothing. Either the credential has left the machine, and the entry should "+
			"go with `faramir link rm REF`, or the home holding it is not mounted: %s",
			len(cfg.Secret.Links)-len(absent), opts.BrokerUser, len(absent),
			strings.Join(absent, ", "))
	default:
		report.addf(name, StatusOK, "%d linked file(s) readable by %s and not by %s",
			len(cfg.Secret.Links), opts.BrokerUser, opts.ExecUser)
	}
}
