package install

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
func unseenFiles(seen map[string]bool, files []agentFile) []agentFile {
	out := make([]agentFile, 0, len(files))
	for _, file := range files {
		if seen[file.path] {
			continue
		}
		seen[file.path] = true
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
		r.step(labelAgentConfig, false, fmt.Sprintf(
			"no coding agent found in %s, so no deny rules were written. "+
				"`faramir init --agent NAME` writes them anyway (%s)",
			r.operatorHome, strings.Join(knownAgents(), ", ")))
		r.step("agent instructions", false, "no coding agent found, so no credentials "+
			"section was written")
		return nil
	}
	// Against the same data a tree's files render against, which carries the
	// layout inside it. An account file that is only a rule list reads the layout
	// and nothing else; one that is a program has to name the binary it execs and
	// the dialect it speaks, and rendering those two kinds differently is a
	// second render path to keep in step.
	asTarget := func(target *agentTarget) func(agentFile) ([]byte, error) {
		return func(file agentFile) ([]byte, error) {
			return renderData(file.asset, pluginData{
				BinDir:        DefaultBinDir,
				Agent:         target.name,
				Family:        target.familyName(),
				Path:          file.path,
				DefaultExport: file.defaultExport,
				Layout:        r.layout,
			})
		}
	}

	changed := false
	var written, refused []string
	seen := map[string]bool{}
	for _, target := range targets {
		files := unseenFiles(seen, target.accountFiles)
		// 0700: these sit in the agent account's home.
		made, paths, err := writeAgentFiles(r.fs, r.warnf, r.operatorHome, r.layout.ConfigDir,
			r.operatorUID, r.operatorGID, 0o700, false, asTarget(target), files)
		written = append(written, paths...)
		stood := true
		switch {
		case errors.Is(err, errNotOperators):
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
		// goes looking for one. See agentTarget.accountNote.
		if target.accountNote != "" && stood {
			r.warnf("%s: %s", target.name, target.accountNote)
		}
	}
	r.step(labelAgentConfig, changed, strings.Join(written, ", "))
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
func (r *runner) agentInstructions(targets []*agentTarget) error {
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
func (r *runner) writeSections(targets []*agentTarget) (bool, []string, []string, error) {
	changed := false
	var written, stale []string
	for _, file := range homeInstructionFiles(targets) {
		section, err := homeSection(r.layout.AllowSudo)
		if err != nil {
			return changed, written, stale, err
		}
		path := filepath.Join(r.operatorHome, file.path)
		// The operator's own group, not keep, and never re-owned: a .pi/agent or
		// .kilocode/rules that does not exist yet would otherwise be created
		// operator:root.
		if _, err := r.fs.ensureDir(
			filepath.Dir(path), 0o700, r.operatorUID, r.operatorGID, false); err != nil {
			return changed, written, stale, err
		}
		made, err := r.fs.sectionFile(path, section, "", r.operatorUID, r.operatorGID, "")
		switch {
		case outOfDate(err):
			// Collected rather than returned, so every other agent's section is
			// still brought up to date and the run fails once at the end naming all
			// of them.
			stale = append(stale, sectionProblem(err, path, "`sudo faramir init`"))
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
func homeInstructionFiles(targets []*agentTarget) []homeInstructionFile {
	var out []homeInstructionFile
	at := map[string]int{}
	for _, target := range targets {
		path := target.homeInstructions
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

// homeSection is the section `init` writes into a home. Rendered rather than
// shipped as it is, for the escalation half: a host that granted no sudo would
// otherwise be telling an agent how to ask for something it cannot have.
//
// It names no path this install decides, the rules it explains being rendered
// into each agent's own config from protectedpaths.go.
func homeSection(allowSudo bool) (string, error) {
	body, err := renderData("agent/instructions.home.md.snippet",
		struct {
			AllowSudo bool
		}{AllowSudo: allowSudo})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
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
	trees, unreadable := readEnrolledWhy(r.layout.ConfigDir)
	var written, skipped, refused []string
	changed := false
	for _, tree := range trees {
		if !exists(tree.Dir) {
			skipped = append(skipped, tree.Dir)
			continue
		}
		// The same question `init-project` asks before it enrols one. The record
		// is advisory and is written by more than one release, so a directory it
		// names is not proof that enrolling it would be allowed today: without
		// this, an entry for one of faramir's own directories has every `init`
		// writing an agent's settings back into it after an operator has cleaned
		// them out.
		if err := refuseInstallDirs(tree.Dir, r.layout.ConfigDir); err != nil {
			refused = append(refused, tree.Dir)
			continue
		}
		if err := refuseOversharing(tree.Dir, tree.AgentUser); err != nil {
			refused = append(refused, tree.Dir)
			continue
		}
		uid, gid := r.operatorUID, r.operatorGID
		if id, err := lookupUser(tree.AgentUser); err == nil && tree.AgentUser != "" {
			uid = id
		}
		if id, _, err := primaryGroup(tree.AgentUser); err == nil && tree.AgentUser != "" {
			gid = id
		}
		for _, name := range tree.Agents {
			target, known := agentTargets[name]
			if !known {
				continue
			}
			asTarget := func(file agentFile) ([]byte, error) {
				return assetFor(target, file, r.layout.ConfigDir)
			}
			made, paths, err := writeAgentFiles(r.fs, r.warnf, tree.Dir, r.layout.ConfigDir,
				uid, gid, 0o2770|os.ModeSetgid, true, asTarget, target.files)
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
		r.step(labelEnrolledTrees, false, "the record of what is enrolled could not "+
			"be read, so no enrolled tree was rewritten and `faramir doctor` reports "+
			"none of them: "+unreadable)
	case len(trees) == 0:
		r.step(labelEnrolledTrees, false, "no tree is recorded as enrolled")
	case len(written) == 0 && len(skipped) == 0:
		r.step(labelEnrolledTrees, false, "nothing to write into "+treeCount(len(trees)))
	default:
		r.step(labelEnrolledTrees, changed, strings.Join(written, ", "))
	}
	if len(refused) > 0 {
		// A different remedy from the one below: this tree is not one an
		// enrolment would make now, so re-running init-project in it would be
		// refused too. The entry is what has to go.
		r.warnf("%d recorded tree(s) are directories `faramir init-project` would "+
			"refuse to enrol, so nothing was written into them: %s. Remove their "+
			"entries from %s, and anything an earlier enrolment left in them",
			len(refused), strings.Join(refused, ", "),
			enrolledPath(r.layout.ConfigDir))
	}
	if len(skipped) > 0 {
		r.warnf("%d enrolled tree(s) were not rewritten, so what an enrolment "+
			"writes there is now one entry short and `faramir doctor` reports "+
			"them: %s. Re-run `sudo faramir init-project` in each once it is "+
			"reachable", len(skipped), strings.Join(skipped, ", "))
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
