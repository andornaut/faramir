package enrol

// What an enrolment writes into the tree: each agent's own configuration, and
// the credentials section in the file it reads for every project.

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/codextrust"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/steps"
)

func warnMissingAccountRules(p *project, target *agentcfg.Target) {
	if len(target.AccountFiles) == 0 {
		return
	}
	home, err := agentcfg.HomeFor(p.opts.AgentUser)
	if err != nil || home == "" {
		return
	}
	var missing []string
	for _, file := range target.AccountFiles {
		if !hostfs.Exists(filepath.Join(home, file.Path)) {
			missing = append(missing, "~/"+file.Path)
		}
	}
	if len(missing) == 0 {
		return
	}
	// What those rules cover is what this install writes, plus whatever a
	// [[secret.link]] or [[secret.block]] entry names: see agentcfg's protected
	// paths,
	// which renders the same set into the bash deny list. Named that way rather
	// than by example, a rule for a path faramir did not choose being the thing
	// that design refuses to compile in.
	p.warnf("%s has no account-wide deny rules (%s missing); its file tools are unguarded until "+
		"faramir init --agent %s runs",
		target.Name, strings.Join(missing, ", "), target.Name)
}

// agentConfig writes each enrolled agent's configuration into the tree. What
// the hook costs differs by agent, Claude Code being the only one with an
// escalation to give, so the warning below names the agent it just enrolled.
func (p *project) agentConfig() error {
	if len(p.targets) == 0 {
		// The tree is shared and the instructions are written either way; what is
		// missing is the hook, and with it the redaction. A warning rather than a
		// step: a step scrolls past with the rest of a successful run, and this
		// enrolment leaves the tree shared with the client group and guarded by
		// nothing. `faramir doctor` reports the same tree for as long as it stays
		// that way.
		p.warnf("no coding agent is configured in %s, so nothing it runs is redacted; "+
			"pass --agent to enrol one (%s)",
			p.opts.Dir, strings.Join(agentcfg.Known(), ", "))
		p.step(steps.LabelAgentConfig, false, "no coding agent is configured in "+p.opts.Dir)
		return nil
	}
	changed := false
	var written []string
	for _, target := range p.targets {
		// Against the target's own data: the installed binary, which agent it
		// speaks to, and where it is written.
		asTarget := func(file agentcfg.File) ([]byte, error) {
			return agentcfg.AssetFor(target, file, p.opts.ConfigDir)
		}
		// Shared and setgid, as the walk leaves every other directory in the tree.
		// 0700 would make a directory created here the one place in an enrolled
		// tree the client group cannot enter, until a later run's walk widened it
		// and reported a change on what reads as a re-enrolment.
		made, paths, err := agentcfg.WriteFiles(p.fs, p.warnf, p.opts.Dir, p.opts.ConfigDir,
			p.uid, p.gid, 0o2770|os.ModeSetgid, true, asTarget, target.Files)
		written = append(written, paths...)
		if err != nil {
			return err
		}
		changed = changed || made
		// Each warning is about this agent, so each asks whether this agent's files
		// changed rather than whether any have.
		if target.AutoApprovesBash && made {
			p.warnf("%s auto-approves Bash in %s; only the deny list can refuse a command",
				target.Name, p.opts.Dir)
		}
		// The account-wide half is `faramir init --agent`'s, and without it the
		// agent's file tools have no rules at all: the deny list covers the
		// operator's own ~/.ssh and ~/.config/sops, which no uid boundary reaches,
		// the agent running as the operator.
		warnMissingAccountRules(p, target)
		// Where the note stands, whether or not this run wrote anything: see
		// agentcfg.Target.NoteStands, and codextrust.NoteStands for the one note
		// the agent itself answers. Both scopes: what this tree's hook is trusted
		// to do says nothing about the account-wide one an earlier `init` wrote,
		// which is inert under the same conditions and guards the file tools
		// wherever the agent is working.
		if target.Note != "" && (made || target.NoteStands) &&
			codextrust.NoteStands(target.Name, p.agentHome, p.opts.Dir, p.agentHome) {
			p.warnf("%s: %s", target.Name, target.Note)
		}
		p.warnUncommittableFiles(target)
	}
	// Named rather than counted, so an operator knows which file to merge.
	p.step(steps.LabelAgentConfig, changed, strings.Join(written, ", "))

	// What auto would have taken and this run did not, which only happens when
	// the operator named agents explicitly.
	var unenrolled []string
	for _, name := range agentcfg.Detected(p.opts.Dir, p.agentHome) {
		enrolled := false
		for _, target := range p.targets {
			// By family: two agents sharing one tree enrolment are covered by
			// whichever of them was named, the files being the same bytes.
			if target.FamilyName() == agentcfg.Targets[name].FamilyName() {
				enrolled = true
			}
		}
		if !enrolled {
			unenrolled = append(unenrolled, name)
		}
	}
	if len(unenrolled) > 0 {
		p.warnf("not enrolled, though configured in this tree: %v; pass --agent to include one",
			unenrolled)
	}
	return nil
}

// warnUncommittableFiles says so when a file this enrolment wrote is one the
// agent treats as yours rather than the repository's, and git is not ignoring
// it. Claude Code adds settings.local.json to the git excludes when it writes
// the file itself; one faramir created is not covered by that.
//
// Said rather than done: what a repository ignores is the operator's to decide,
// and writing into .git or a tracked .gitignore is not this command's to do.
// Nothing in the file is secret, only specific to this machine: the binary the
// hook execs, and the directories this install occupies.
func (p *project) warnUncommittableFiles(target *agentcfg.Target) {
	for _, file := range target.Files {
		if !file.Local || p.isIgnored(file.Path) {
			continue
		}
		p.warnf("%s is machine-specific and not git-ignored; add it to .gitignore or .git/info/exclude",
			file.Path)
	}
}

// isIgnored asks git, which is the only thing that can answer: the rule may be
// in a .gitignore at any level, in .git/info/exclude, or in the operator's
// global excludes.
//
// Exit 0 is ignored and exit 1 is not; anything else is git declining to answer,
// which a tree that is no repository and a host with no git both are. Those
// answer true, so the warning is withheld rather than guessed at.
func (p *project) isIgnored(rel string) bool {
	// --no-index, or a file already committed is reported as not ignored on the
	// strength of being tracked, which is not the question being put.
	cmd := exec.CommandContext(context.Background(), "git", "-C", p.opts.Dir,
		"check-ignore", "--quiet", "--no-index", "--", rel)
	err := cmd.Run()
	if err == nil {
		return true
	}
	var exit *exec.ExitError
	if errors.As(err, &exit) && exit.ExitCode() == 1 {
		return false
	}
	return true
}

// instructions writes the credentials section into the files this project's
// agents read as prose, between markers so a later run replaces what an earlier
// one wrote. Documentation, not enforcement: deleting the block changes
// nothing about what is reachable.
func (p *project) instructions() error {
	if p.opts.ConfigDir != "" {
		if _, err := agentcfg.ReadEnrolledWhy(p.opts.ConfigDir); err != nil {
			return err
		}
	}
	// One block for every agent, rendered once.
	section, err := agentcfg.CredentialsSection(p.allowSudo)
	if err != nil {
		return err
	}
	// Shared policy is written once, followed by every enabled harness's notes.
	targets := p.enabledTargets()
	if len(targets) > 0 {
		var combined strings.Builder
		combined.WriteString(section)
		combined.WriteString("\n## Enabled harnesses\n\n")
		for _, target := range targets {
			combined.WriteString("- " + target.Name)
			var notes []string
			if target.AutoApprovesBash {
				notes = append(notes, "Bash routing auto-approves commands except deny-list refusals.")
			}
			if target.Note != "" {
				notes = append(notes, target.Note)
			}
			if len(notes) > 0 {
				combined.WriteString(": " + strings.Join(notes, " "))
			}
			combined.WriteByte('\n')
		}
		section = combined.String()
	}
	changed, written, stale, err := p.writeSections(section)
	// Recorded before the failure, so a report says what was written as well as
	// what was not.
	p.step("instructions", changed, strings.Join(written, ", "))
	switch {
	case err != nil:
		return err
	case len(stale) > 0:
		return errors.New(strings.Join(stale, "\n"))
	}
	p.warnLegacyInstructions()
	return nil
}

// Adding a harness preserves still-enabled enrollments without restoring a
// routing configuration the operator removed. Global-only harnesses have no
// project routing file, so their enrollment record remains the evidence.
func (p *project) enabledTargets() []*agentcfg.Target {
	byName := map[string]*agentcfg.Target{}
	for _, target := range p.targets {
		byName[target.Name] = target
	}
	if p.opts.ConfigDir != "" {
		for _, tree := range agentcfg.ReadEnrolled(p.opts.ConfigDir) {
			if tree.Dir != p.opts.Dir {
				continue
			}
			for _, name := range tree.Agents {
				if target := agentcfg.Targets[name]; target != nil {
					if !agentcfg.StillEnrolled(p.opts.Dir, name) {
						continue
					}
					byName[name] = target
				}
			}
		}
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)
	out := make([]*agentcfg.Target, 0, len(names))
	for _, name := range names {
		out = append(out, byName[name])
	}
	return out
}

// Legacy directory entries are retained for operator migration. Only an alias
// of the canonical file can receive its shared section through the same target.
func (p *project) warnLegacyInstructions() {
	home := p.agentHome
	if home != "" {
		if resolved, err := filepath.EvalSymlinks(home); err == nil {
			home = resolved
		}
	}
	for dir := p.opts.Dir; ; dir = filepath.Dir(dir) {
		for _, rel := range []string{"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".claude/CLAUDE.md", ".agents/rules/faramir.md"} {
			// The native user-level Claude file is not a project override.
			if (dir == home || dir == p.agentHome) && rel == agentcfg.Targets["claude"].HomeInstructions {
				continue
			}
			path := filepath.Join(dir, rel)
			if _, err := os.Lstat(path); err == nil {
				p.warnf("legacy project instructions at %s remain in place; before cleanup, make AGENTS.md a regular file containing the complete user text and managed credentials section. Then remove only obsolete project files or symlinks; keep global harness files", path)
			}
		}
		if parent := filepath.Dir(dir); parent == dir {
			break
		}
	}
}

// writeSections writes the section into each file, and reports what it wrote,
// what it left as it is, and what stopped it.
func (p *project) writeSections(section string) (bool, []string, []string, error) {
	changed := false
	var written, stale []string
	for _, file := range p.instructionsFiles() {
		// Shared and setgid at every level, as the walk leaves the rest of the
		// tree: see agentConfig and ensureDirs. An agent whose rules file sits
		// under a directory none of its config files do -- antigravity's
		// .agents/rules -- has this as the only thing that creates it, and it
		// holds a file this wrote, so it is sticky like the rest of them.
		if err := p.fs.EnsureDirsIn(p.opts.Dir, filepath.Dir(file.Path),
			0o2770|os.ModeSetgid, 0o2770|os.ModeSetgid|os.ModeSticky,
			p.uid, p.gid); err != nil {
			return changed, written, stale, err
		}
		made, err := agentcfg.SectionFile(p.fs,
			file.Path, section, file.Head, p.uid, p.gid, p.opts.Dir)
		switch {
		case agentcfg.OutOfDate(err):
			// Collected rather than returned: an operator fixing these wants every
			// file named, and one agent's rules file cannot cost the tree its own
			// instructions.
			stale = append(stale, agentcfg.SectionProblem(err, file.Path, "`sudo faramir enrol`"))
			written = append(written, file.Path+" (not written; see the error)")
			continue
		case err != nil:
			return changed, written, stale, err
		}
		changed = changed || made
		written = append(written, file.Path)
	}
	return changed, written, stale, nil
}

// instructionsFiles are the files this enrolment writes the credentials section
// into: the tree's own, and one per agent that reads none of the names at the
// tree's root. Absolute, and in a fixed order.
func (p *project) instructionsFiles() []agentcfg.SectionTarget {
	out := []agentcfg.SectionTarget{{Path: p.instructionsFile()}}
	for _, target := range p.targets {
		if rules := target.TreeInstructions; rules.Path != "" {
			out = append(out, agentcfg.SectionTarget{
				Path: filepath.Join(p.opts.Dir, rules.Path), Head: rules.Head,
			})
		}
	}
	return agentcfg.OneSectionPerFile(out)
}

// relativeInstructions is instructionsFiles as sharetree and agentcfg.RefuseUnwritable
// take them: relative to the tree.
func (p *project) relativeInstructions() ([]string, error) {
	var out []string
	for _, file := range p.instructionsFiles() {
		rel, err := filepath.Rel(p.opts.Dir, file.Path)
		if err != nil {
			return nil, err
		}
		out = append(out, rel)
	}
	return out, nil
}

func (p *project) instructionsFile() string { return agentcfg.TreeInstructionsFile(p.opts.Dir) }
