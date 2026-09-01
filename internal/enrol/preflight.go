package enrol

// Everything settled before the share, which chowns and chmods every file in
// the tree and cannot be undone: the refusals, and the group and ids the rest
// of the run writes as. Finding out afterwards that a settings file is not the
// operator's is finding out too late.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"slices"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/sharetree"
)

// preflight is every refusal this command can make, asked before the walk that
// cannot be undone: a check that fails at its own step leaves a half-enrolled
// tree.
func (p *project) preflight() error {
	if p.opts.AgentUser == "" || p.opts.AgentUser == "root" {
		return fmt.Errorf("no account is named for %s: run through sudo so SUDO_USER "+
			"carries it, or record the account with `faramir init --agent-user`. Root "+
			"here would chown a checkout away from its owner", p.opts.Dir)
	}
	if os.Geteuid() != 0 && !p.opts.DryRun {
		return errors.New("faramir enrol must run as root: it " +
			"changes group ownership and modes on the tree it enrols")
	}
	if err := RefuseOversharing(p.opts.Dir, p.opts.AgentUser); err != nil {
		return err
	}
	if err := RefuseInstallDirs(p.opts.Dir, p.opts.ConfigDir); err != nil {
		return err
	}
	// auto looks at the tree, enrolling costing something here. Resolved before
	// anything is written, so an unknown name stops the run before the tree's
	// ownership changes.
	// Not fatal: an account that does not resolve fails later with a message
	// about the account, and auto losing one agent is not the error to report
	// here.
	p.agentHome, _ = agentcfg.HomeFor(p.opts.AgentUser)
	targets, err := agentcfg.Resolve(p.opts.Agents, agentcfg.ScopeTree, p.opts.Dir, p.agentHome)
	if err != nil {
		return err
	}
	p.targets = targets
	if err := p.resolveGroup(); err != nil {
		return err
	}
	if err := p.resolveIDs(); err != nil {
		return err
	}
	if err := p.refuseUnreachable(); err != nil {
		return err
	}
	p.warnMissingBinary(filepath.Join(hostlayout.DefaultBinDir, "faramir"))
	if err := p.refuseUnwritableFiles(); err != nil {
		return err
	}
	return p.refuseUnparsableAgentConfig()
}

// refuseUnparsableAgentConfig asks, before the share, the other question every
// merge into this tree will ask. faramir writes its keys into the agent's own
// file rather than replacing it, so a file that does not parse is refused, and
// finding that out at the write is too late: the share has already handed the
// client group read and write on every file in the tree, and the run then stops
// without registering the hook that was the point of it, leaving a tree open
// and guarded by nothing.
//
// Only a parse failure. A file that cannot be read or is not the operator's is
// refuseUnwritableFiles's to name, and saying it twice would put one problem in
// front of the operator under two headings.
func (p *project) refuseUnparsableAgentConfig() error {
	var refused []string
	for _, target := range p.targets {
		for _, file := range target.Files {
			if !file.Merge {
				continue
			}
			path := filepath.Join(p.opts.Dir, file.Path)
			spot, err := p.fs.EditedFile(path, p.uid, p.opts.Dir)
			if err != nil {
				spot.Close()
				continue
			}
			data, readErr := spot.Read()
			spot.Close()
			if readErr != nil || len(bytes.TrimSpace(data)) == 0 {
				continue
			}
			var into any
			if err := json.Unmarshal(data, &into); err != nil {
				refused = append(refused, fmt.Sprintf(
					"%s: parsing the file already there: %v. faramir merges its keys "+
						"into this file rather than replacing it, so nothing was written "+
						"and the tree was not shared", path, err))
			}
		}
	}
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// refuseUnreachable stops an enrolment that would share a tree nothing can
// reach. A home is 0700, so every directory between it and the tree has to let
// the client group through, and group execute on the tree grants nothing while
// a directory above it refuses the traversal.
//
// Reported rather than opened: the enrolled tree is the one place faramir
// changes ownership and modes, and those directories are outside it. Whoever
// manages the host's permissions sets them.
func (p *project) refuseUnreachable() error {
	if p.opts.DryRun {
		return nil
	}
	blocked, err := sharetree.Traversable(sharetree.Options{
		Dir: p.opts.Dir, Operator: p.opts.AgentUser, Group: p.report.ClientGroup,
	})
	if err != nil {
		return fmt.Errorf("%s: %w", p.opts.Dir, err)
	}
	if len(blocked) == 0 {
		return nil
	}
	return fmt.Errorf("%s cannot enter %s, so %s would be shared and unreachable. "+
		"faramir changes ownership and modes on the tree it enrols and nowhere "+
		"else; open them and run this again:\n%s",
		p.report.ClientGroup, sharetree.Describe(blocked), p.opts.Dir,
		sharetree.Fix(blocked, p.report.ClientGroup))
}

// refuseUnwritableFiles asks, before the share, the question every write into
// this tree will ask: the share chowns and chmods every file in the tree and
// nothing undoes it, so finding out afterwards that a settings file is not the
// operator's is too late.
func (p *project) refuseUnwritableFiles() error {
	paths, err := p.relativeInstructions()
	if err != nil {
		return err
	}
	for _, target := range p.targets {
		paths = append(paths, agentcfg.EditedPaths(target, true, "")...)
	}
	refused := agentcfg.RefuseUnwritable(p.fs, p.opts.Dir, p.uid, p.opts.Dir, paths)
	// The mode the share settles on, so what this asks is what the write asks.
	refused = append(refused, hostfs.RefuseUnenterableDirs(
		p.opts.Dir, 0o2770|os.ModeSetgid, p.uid, p.gid, paths)...)
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// resolveIDs turns the operator and the client group into ids, before anything
// is written with them. A dry run is allowed to fail here and carry on, so a
// tree can be asked about on a host that has not been provisioned yet: the ids
// stay keep, and nothing a dry run reaches writes.
func (p *project) resolveIDs() error {
	uid, err := hostfs.LookupUser(p.opts.AgentUser)
	if err != nil {
		if p.opts.DryRun {
			return nil
		}
		return err
	}
	gid, err := hostfs.LookupGroup(p.report.ClientGroup)
	if err != nil {
		if p.opts.DryRun {
			return nil
		}
		return err
	}
	p.uid, p.gid = uid, gid
	return nil
}

// warnMissingBinary says so when the binary every agent's hook and plugin is
// about to be pointed at is not installed. Warned rather than refused:
// --client-group enrols a tree for an install that need not be on this machine.
// On the host that runs it the hook and the plugins fail closed, refusing every
// command in the project rather than running one unredacted.
func (p *project) warnMissingBinary(binary string) {
	if hostfs.Exists(binary) {
		return
	}
	p.warnf("%s is not installed, and every hook and plugin written here execs it. "+
		"They fail closed, so the agents would refuse every command in %s. Run "+
		"`sudo faramir init` on the host that runs this tree", binary, p.opts.Dir)
}

// RefuseOversharing stops an enrolment that would share far more than a
// project. Sharing grants the client group read and write on every file in the
// tree, and faramir-exec is in that group: for a home that is ~/.ssh,
// ~/.config/sops/age/keys.txt, and group write on the shell configuration that
// decides what the operator's next login runs. Blocked rather than warned
// about, the walk not being reversible.
func RefuseOversharing(dir, operator string) error {
	tooBig := func(what string) error {
		return fmt.Errorf("refusing to enrol %s: it is %s. Enrolling gives the client group read and write "+
			"on every file in it. Name the project directory instead", dir, what)
	}
	switch dir {
	case "/":
		return tooBig("the root of the filesystem")
	case "/home":
		return tooBig("every home on this host")
	}
	if slices.Contains(systemRoots, dir) {
		return tooBig("a system directory rather than a project")
	}
	if home := hostlayout.HomeOf(dir); home == dir {
		return tooBig("a home directory")
	}
	// The account's own home as passwd records it, which catches one outside
	// /home and /root. Resolved, because dir is. An unknown account fails later
	// in shareTree, with the error that names it.
	if entry, err := user.Lookup(operator); err == nil && entry.HomeDir != "" {
		home, err := sharetree.Resolve(entry.HomeDir)
		if err != nil {
			home = filepath.Clean(entry.HomeDir)
		}
		if home == dir {
			return tooBig(operator + "'s home directory")
		}
		if hostfs.Encloses(dir, home) {
			return tooBig("above " + operator + "'s home directory")
		}
	}
	return nil
}

// systemRoots are the directories a walk must not be pointed at. Sharing chowns
// the directory to the operator, chmods it 2770 and applies g+rwX to everything
// under it, so one of these regrouped is a host repaired from outside faramir
// or not at all.
//
// Named rather than derived from "outside /home": a checkout on shared storage
// is a tree an operator may legitimately enrol, needing the drop-in extending
// ReadWritePaths= that shareTree warns about. /root is absent, homeOf naming it
// as the home it is.
//
// The merged-/usr targets are listed with the links that point at them: the
// directory reaching this has been through sharetree.Resolve, so /bin arrives
// as /usr/bin on most hosts and as itself on the rest.
var systemRoots = []string{
	"/bin", "/boot", "/dev", "/etc", "/lib", "/lib32", "/lib64", "/libx32",
	"/opt", "/proc", "/run", "/sbin", "/snap", "/srv", "/sys", "/tmp",
	"/usr", "/var",
	"/usr/bin", "/usr/include", "/usr/lib", "/usr/lib32", "/usr/lib64",
	"/usr/libx32", "/usr/local", "/usr/sbin", "/usr/share", "/var/tmp",
}

// RefuseInstallDirs stops an enrolment that would walk faramir's own
// directories. The age key is 0400 and keeper-owned, and sharing ORs group read
// and write onto every file in the tree and regroups it: one walk over the
// config directory hands the client group, which faramir-exec is in, the key
// that decrypts every managed file.
//
// Both directions. A tree above one of these reaches it through the walk, and a
// tree inside one is part of it. systemRoots names /etc and its kind; this
// names what an install puts inside them, and reaches a --config-dir moved
// under a home, which no fixed list can name.
func RefuseInstallDirs(dir, configDir string) error {
	// BinDir with them: it holds the binary every hook and plugin execs, and
	// group write there is a brokered command replacing what the agent runs.
	//
	// agentcfg.RuleLayout rather than the config directory alone: it reads the service
	// accounts off the installed units, so a host that renamed one has the
	// directory it moved to refused rather than the one it left.
	dirs := append(agentcfg.Dirs(agentcfg.RuleLayout(configDir)), hostlayout.DefaultBinDir)
	for _, installed := range dirs {
		installed = filepath.Clean(installed)
		holds := hostfs.Encloses(dir, installed)
		if !holds && !hostfs.Encloses(installed, dir) {
			continue
		}
		relation := "holds"
		switch {
		case installed == dir:
			relation = "is"
		case !holds:
			relation = "is inside"
		}
		return fmt.Errorf("refusing to enrol %s: it %s %s, which is faramir's own. Enrolling gives the "+
			"client group read and write on every file in it, and faramir-exec is in that "+
			"group. Name the project directory instead", dir, relation, installed)
	}
	return nil
}

// resolveGroup reads the shared group out of the installed config.
// allowed_group is what the broker socket admits, so it is the only value that
// makes a shared tree usable. The sudo grant is read from the same load,
// [sudo] exec_user being the switch for the whole arrangement.
//
// The config has to load, --client-group or not. It is where the linked and
// blocked paths are, and those are rules an enrolment writes into the tree: a
// tree enrolled without them carries a deny list that names the built-in paths
// and not the credential file this install added, which reads exactly like one
// that covers everything. --client-group overrides the group it found, and is
// not a way to enrol against no config at all.
func (p *project) resolveGroup() error {
	configFile := filepath.Join(p.opts.ConfigDir, "config.toml")
	cfg, err := config.Load(configFile)
	if err != nil {
		// A dry run writes nothing, so it has no incomplete rules to prevent, and
		// asking about a tree from a host that has not been provisioned yet is what
		// it is for. The same latitude resolveIDs takes.
		if p.opts.DryRun {
			p.warnf("cannot read %s (%v), so this reports on the tree alone",
				configFile, err)
			p.report.ClientGroup = p.opts.ClientGroup
			return nil
		}
		return fmt.Errorf("cannot read %s: %w\nAn enrolment writes this install's deny rules into the tree, "+
			"and the linked and blocked paths are in that file. Run `faramir init` first, or "+
			"set FARAMIR_CONFIG if the config is elsewhere", configFile, err)
	}
	// The grant is this host's, and says nothing about a tree shared with a group
	// this host's socket does not admit: that names another install, whose
	// escalation arrangement is its own.
	if p.opts.ClientGroup == "" || cfg.Server.AllowedGroup == p.opts.ClientGroup {
		p.allowSudo = cfg.Sudo.ExecUser != ""
	}
	if p.opts.ClientGroup != "" {
		p.report.ClientGroup = p.opts.ClientGroup
		return nil
	}
	if cfg.Server.AllowedGroup == "" {
		return fmt.Errorf("%s admits no group, so a shared tree would reach nothing. "+
			"Run `faramir init --client-group NAME`", configFile)
	}
	p.report.ClientGroup = cfg.Server.AllowedGroup
	return nil
}
