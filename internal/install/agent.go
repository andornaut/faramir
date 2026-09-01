package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/enroll"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/steps"
)

// stepAgentConfig registers the broker with the operator's own account, which
// is what the coding agent runs as. Only the deny rules go here: they refuse
// to open or overwrite key material wherever the agent is working. The
// PreToolUse hook is per-project, registering it auto-approving Bash there.
// unseenFiles is the account files this run has not written yet, marking each
// one it returns. Two agents may read one file: the Antigravity family shares
// the hook both halves load for every workspace, and the CLI has deny rules of
// its own beside it. Written once, and named once in the report, a file listed
// twice reading as two files to check.
//
// By path rather than by asset: what matters is the file on disk, and two
// targets rendering the same path from different assets would still be one
// write, the second overwriting the first.
func unseenFiles(seen map[string]bool, files []agentcfg.File) []agentcfg.File {
	out := make([]agentcfg.File, 0, len(files))
	for _, file := range files {
		if seen[file.Path] {
			continue
		}
		seen[file.Path] = true
		out = append(out, file)
	}
	return out
}

func (r *runner) stepAgentConfig() error {
	// Whichever agents this home carries, unless one is named, resolved in
	// stepPreconditions. Detecting rather than writing them all costs an agent
	// installed afterwards its rules until somebody re-runs this, which `faramir
	// doctor` reports as a failure naming the command.
	targets := r.agentTargets
	if len(targets) == 0 {
		// Not an error and not a silent pass: nothing was written, and the reason
		// is a home with no agent in it.
		r.step(steps.LabelAgentConfig, false, fmt.Sprintf(
			"no coding agent found in %s, so no deny rules were written. "+
				"`faramir init --agent NAME` writes them anyway (%s)",
			r.operatorHome, strings.Join(agentcfg.Known(), ", ")))
		r.step("agent instructions", false, "no coding agent found, so no credentials "+
			"section was written")
		return nil
	}
	// Against the same data a tree's files render against, which carries the
	// layout inside it. An account file that is only a rule list reads the layout
	// and nothing else; one that is a program has to name the binary it execs and
	// the dialect it speaks, and rendering those two kinds differently is a
	// second render path to keep in step.
	asTarget := func(target *agentcfg.Target) func(agentcfg.File) ([]byte, error) {
		return func(file agentcfg.File) ([]byte, error) {
			return agentcfg.RenderData(file.Asset, agentcfg.PluginData{
				BinDir:        hostlayout.DefaultBinDir,
				Agent:         target.Name,
				Family:        target.FamilyName(),
				Path:          file.Path,
				DefaultExport: file.DefaultExport,
				Layout:        r.layout,
			})
		}
	}

	changed := false
	var written, refused []string
	seen := map[string]bool{}
	for _, target := range targets {
		files := unseenFiles(seen, target.AccountFiles)
		// 0700: these sit in the agent account's home.
		made, paths, err := agentcfg.WriteFiles(r.fs, r.warnf, r.operatorHome, r.layout.ConfigDir,
			r.operatorUID, r.operatorGID, 0o700, false, asTarget(target), files)
		written = append(written, paths...)
		stood := true
		switch {
		case errors.Is(err, hostfs.ErrNotOperators):
			// Collected rather than returned, as the sections below are: every other
			// agent's rules are still written and the run fails once at the end
			// naming all of them.
			refused = append(refused, err.Error())
			stood = false
		case err != nil:
			return err
		}
		changed = changed || made
		// Whether or not this run wrote anything, but not where the write was
		// refused: what the note describes is a condition the agent is under rather
		// than something this run just did, and nothing here can check it has been
		// met -- but told to go and trust a hook that was never written, an operator
		// goes looking for one. See agentcfg.Target.AccountNote.
		if target.AccountNote != "" && stood {
			r.warnf("%s: %s", target.Name, target.AccountNote)
		}
	}
	r.step(steps.LabelAgentConfig, changed, strings.Join(written, ", "))
	// The sections first, so one refused rule file does not cost every agent its
	// instructions, and then both halves together: an operator who fixes the rule
	// files should not then meet section failures they were never shown.
	if err := r.agentInstructions(targets); err != nil {
		refused = append(refused, err.Error())
	}
	if len(refused) > 0 {
		return errors.New(strings.Join(refused, "\n"))
	}
	return nil
}

// agentInstructions writes the account-wide credentials section into the file
// each enrolled agent reads, once per file rather than once per agent: two of
// them can name the same one.
//
// The rules written above refuse the file tools; this is what an agent is told
// about them. Without it a refusal on ~/.ssh/id_ed25519 reaches the model as a
// bare permission error, which is the shape that invites a second attempt
// through an interpreter or a base64 pipe. Kept short: this loads into every
// session on the machine.
func (r *runner) agentInstructions(targets []*agentcfg.Target) error {
	changed, written, stale, err := r.writeSections(targets)
	// Recorded before the failure, so a report says what was written as well as
	// what was not.
	r.step("agent instructions", changed, strings.Join(written, ", "))
	switch {
	case err != nil:
		return err
	case len(stale) > 0:
		return errors.New(strings.Join(stale, "\n"))
	}
	return nil
}

// writeSections writes the section into each file, and reports what it wrote,
// what it left as it is, and what stopped it.
func (r *runner) writeSections(targets []*agentcfg.Target) (bool, []string, []string, error) {
	changed := false
	var written, stale []string
	for _, file := range homeInstructionFiles(targets) {
		section, err := agentcfg.HomeSection(r.layout.AllowSudo)
		if err != nil {
			return changed, written, stale, err
		}
		path := filepath.Join(r.operatorHome, file.path)
		// The operator's own group, not keep, and never re-owned: a .pi/agent or
		// .kilocode/rules that does not exist yet would otherwise be created
		// operator:root.
		if _, err := r.fs.EnsureDir(
			filepath.Dir(path), 0o700, r.operatorUID, r.operatorGID, false); err != nil {
			return changed, written, stale, err
		}
		made, err := agentcfg.SectionFile(r.fs, path, section, "", r.operatorUID, r.operatorGID, "")
		switch {
		case agentcfg.OutOfDate(err):
			// Collected rather than returned, so every other agent's section is
			// still brought up to date and the run fails once at the end naming all
			// of them.
			stale = append(stale, agentcfg.SectionProblem(err, path, "`sudo faramir init`"))
			written = append(written, path+" (not written; see the error)")
			continue
		case err != nil:
			return changed, written, stale, err
		}
		changed = changed || made
		written = append(written, path)
	}
	return changed, written, stale, nil
}

// homeInstructionFile is one file to write the account-wide section into, and
// what the section may claim in it.
type homeInstructionFile struct {
	// path is relative to the agent account's home.
	path string
}

// homeInstructionFiles are the files these agents read, one entry per file.
//
// Grouped rather than written per agent: nothing stops two agents reading one
// file, and written per agent the same span would be rewritten twice in one run
// with the last agent's claim about the deny rules left standing. No two share
// one today; the rule stays because the failure it prevents is silent.
//
// This is the same path named twice, which is one file written once. Two
// different paths that a link makes one file are refused before anything is
// written: see oneFileTwice.
//
// One file, once, in the order the targets came in, so a report reads the same
// twice. Every agent has something account-wide, so the section makes the same
// claim whichever of them reads it.
func homeInstructionFiles(targets []*agentcfg.Target) []homeInstructionFile {
	var out []homeInstructionFile
	at := map[string]int{}
	for _, target := range targets {
		path := target.HomeInstructions
		if path == "" {
			continue
		}
		if _, seen := at[path]; seen {
			continue
		}
		at[path] = len(out)
		out = append(out, homeInstructionFile{path: path})
	}
	return out
}

// stepEnrolledTrees re-renders the project files of every tree this install has
// enrolled, so a rule declared after the enrolment reaches the trees as well as
// the home.
//
// An enrolment writes the same deny rules into the tree that `init` writes into
// the home. Declaring a blocked path or a linked file afterwards rewrote the
// home alone, and every enrolled tree then carried a rule set one entry short:
// `faramir doctor` reported each of them as drifted, and the remedy was to run
// `init-project` again in each tree by hand. The install already records where
// they are, so it can write them itself.
//
// Best effort per tree. A checkout that has moved, been deleted, or become
// unreadable is not a reason to fail the command that declared the entry: the
// config and the home are written either way, and doctor reports a tree that
// still does not carry what an enrolment writes.
func (r *runner) stepEnrolledTrees() error {
	trees, unreadableErr := agentcfg.ReadEnrolledWhy(r.layout.ConfigDir)
	unreadable := ""
	if unreadableErr != nil {
		unreadable = unreadableErr.Error()
	}
	var written, skipped, refused []string
	changed := false
	for _, tree := range trees {
		if !hostfs.Exists(tree.Dir) {
			skipped = append(skipped, tree.Dir)
			continue
		}
		// The same question `init-project` asks before it enrols one. The record
		// is advisory and is written by more than one release, so a directory it
		// names is not proof that enrolling it would be allowed today: without
		// this, an entry for one of faramir's own directories has every `init`
		// writing an agent's settings back into it after an operator has cleaned
		// them out.
		if err := enroll.RefuseInstallDirs(tree.Dir, r.layout.ConfigDir); err != nil {
			refused = append(refused, tree.Dir)
			continue
		}
		if err := enroll.RefuseOversharing(tree.Dir, tree.AgentUser); err != nil {
			refused = append(refused, tree.Dir)
			continue
		}
		uid, gid := r.operatorUID, r.operatorGID
		if id, err := hostfs.LookupUser(tree.AgentUser); err == nil && tree.AgentUser != "" {
			uid = id
		}
		if id, _, err := hostfs.PrimaryGroup(tree.AgentUser); err == nil && tree.AgentUser != "" {
			gid = id
		}
		for _, name := range tree.Agents {
			target, known := agentcfg.Targets[name]
			if !known {
				continue
			}
			asTarget := func(file agentcfg.File) ([]byte, error) {
				return agentcfg.AssetFor(target, file, r.layout.ConfigDir)
			}
			made, paths, err := agentcfg.WriteFiles(r.fs, r.warnf, tree.Dir, r.layout.ConfigDir,
				uid, gid, 0o2770|os.ModeSetgid, true, asTarget, target.Files)
			if err != nil {
				skipped = append(skipped, tree.Dir+" ("+err.Error()+")")
				continue
			}
			written = append(written, paths...)
			changed = changed || made
		}
	}
	switch {
	case unreadable != "":
		// Said rather than reported as an empty record: the trees are enrolled
		// either way, and nothing here or in doctor will look at them again until
		// the file is readable.
		r.step(steps.LabelEnrolledTrees, false, "the record of what is enrolled could not "+
			"be read, so no enrolled tree was rewritten and `faramir doctor` reports "+
			"none of them: "+unreadable)
	case len(trees) == 0:
		r.step(steps.LabelEnrolledTrees, false, "no tree is recorded as enrolled")
	case len(written) == 0 && len(skipped) == 0:
		r.step(steps.LabelEnrolledTrees, false, "nothing to write into "+treeCount(len(trees)))
	default:
		r.step(steps.LabelEnrolledTrees, changed, strings.Join(written, ", "))
	}
	if len(refused) > 0 {
		// A different remedy from the one below: this tree is not one an
		// enrolment would make now, so re-running init-project in it would be
		// refused too. The entry is what has to go.
		r.warnf("%d recorded tree(s) `faramir init-project` would refuse to enrol, "+
			"so they were left alone: %s. Remove their entries from %s, and anything "+
			"an earlier enrolment left in them",
			len(refused), strings.Join(refused, ", "),
			agentcfg.EnrolledPath(r.layout.ConfigDir))
	}
	if len(skipped) > 0 {
		r.warnf("%d enrolled tree(s) were not rewritten and are now stale: %s. "+
			"Re-run `sudo faramir init-project` in each once it is reachable",
			len(skipped), strings.Join(skipped, ", "))
	}
	return nil
}

// treeCount is the phrase the step above uses, so "1 tree" does not read as
// "1 trees".
func treeCount(n int) string {
	if n == 1 {
		return "1 enrolled tree"
	}
	return strconv.Itoa(n) + " enrolled trees"
}
