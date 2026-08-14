package install

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"
)

// stepAgentConfig registers the broker with the operator's own account, which is
// what the coding agent runs as.
//
// Only the deny rules go here: they refuse to open or overwrite key material
// wherever the agent is working, and take nothing else away.  The PreToolUse
// hook is per-project, because a rewritten command matches no Bash permission
// rule, so registering it auto-approves Bash for that project.
func (r *runner) stepAgentConfig() error {
	// Whichever agents this home carries, unless one is named.  These rules
	// refuse the file tools, and what they cover is the operator's own key
	// material, which no uid boundary reaches.
	//
	// The cost of detecting rather than writing them all: an agent installed
	// after this ran has no rules until somebody re-runs it.  That state is not
	// silent -- `faramir doctor` reports an agent in the home whose rules are
	// missing as a failure, and names the command -- and the alternative is
	// writing configuration into a home for four agents the operator does not
	// use, which is not this command's to do.
	// Resolved in stepPreconditions, which asked of these same files the question
	// this one is about to answer.
	targets := r.agentTargets
	if len(targets) == 0 {
		// Not an error and not a silent pass: nothing was written, and the reason
		// is a home with no agent in it rather than a step that did its job.
		r.step("agent config", false, fmt.Sprintf(
			"no coding agent found in %s, so no deny rules were written. "+
				"`faramir init --agent NAME` writes them anyway (%s)",
			r.operatorHome, strings.Join(knownAgents(), ", ")))
		r.step("agent instructions", false, "no coding agent found, so no credentials "+
			"section was written")
		return nil
	}
	// Against the install layout: what an account file interpolates is the paths
	// this install decided on.
	asLayout := func(file agentFile) ([]byte, error) { return render(file.asset, r.layout) }

	changed := false
	var written, refused []string
	for _, target := range targets {
		// 0700: these sit in the agent account's home, which no other account has
		// business entering.
		made, paths, err := writeAgentFiles(r.fs, r.operatorHome,
			r.operatorUID, r.operatorGID, 0o700, false, asLayout, target.accountFiles)
		written = append(written, paths...)
		switch {
		case errors.Is(err, errNotOperators):
			// Collected rather than returned, as the sections below are.  Every
			// other agent's rules are still written, the step is still reported,
			// and the run fails once at the end naming all of them: returning here
			// would leave a report that never says what did land, and would take
			// the sections with it, including for the agents whose files were fine.
			refused = append(refused, err.Error())
		case err != nil:
			return err
		}
		changed = changed || made
	}
	r.step("agent config", changed, strings.Join(written, ", "))
	// The sections first, so one refused rule file does not cost every agent its
	// instructions, and then everything this run could not put right, both halves
	// together: an operator who fixes the rule files and re-runs should not then
	// meet the section failures they were never shown.
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
// The rules written above are what refuse the file tools; this is what an agent
// is told about them.  Without it a refusal on ~/.ssh/id_ed25519 reaches the
// model as its own permission error and nothing else, which is the shape that
// invites a second attempt through an interpreter or a base64 pipe.  It is also
// the only thing faramir says in a tree `init-project` has never been run in.
//
// Kept short on purpose: this loads into every session on the machine, and the
// route that does exist is named where it exists, in the enrolled tree's own
// instructions.
func (r *runner) agentInstructions(targets []*agentTarget) error {
	changed, written, stale, err := r.writeSections(targets)
	// Recorded before the failure, so a report says what was written as well as
	// what was not.  Every return below it, including the ones that stop the run
	// outright, leaves a report that names what did land.
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
		section, err := homeSection(file.accountRules)
		if err != nil {
			return changed, written, stale, err
		}
		path := filepath.Join(r.operatorHome, file.path)
		// The operator's own group, not keep, and never re-owned: same reason as
		// the rule files above.  A .pi/agent or .kilocode/rules that does not
		// exist yet would otherwise be created operator:root.
		if _, err := r.fs.ensureDir(
			filepath.Dir(path), 0o700, r.operatorUID, r.operatorGID, false); err != nil {
			return changed, written, stale, err
		}
		made, err := r.fs.sectionFile(path, section, "", r.operatorUID, r.operatorGID, "")
		switch {
		case outOfDate(err):
			// Collected rather than returned here, so every other agent's section
			// is still brought up to date and the run fails once at the end naming
			// all of them.  An operator fixing these wants the whole list.
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
	// accountRules is whether every agent reading this file has deny rules in
	// this home.
	accountRules bool
}

// homeInstructionFiles are the files these agents read, one entry per file.
//
// Grouped rather than written per agent, two agents being able to name the same
// one: an agent's global instructions file is whatever that agent reads, and
// nothing stops two of them reading one.  Written per agent, the same span
// would be rewritten twice in one run and the last agent's claim about the deny
// rules would be the one left, whichever agent then read it.
//
// No two share one today.  The rule stays because the failure it prevents is
// silent: the file would carry a claim, the run would report success, and the
// agent reading it is the one that finds out.
//
// This is the same path named twice, which is one file written once.  Two
// different paths that a link makes one file are refused instead, before
// anything is written: see oneFileTwice.  What can be reconciled is, and what
// cannot stops the run.
//
// So the claim is the weaker of the two: asserted only where every agent
// reading the file has rules in this home.  An agent told it is refused
// everywhere, and finding it is not, has no reason to believe the next claim;
// one told to assume nothing stops it has been told the truth either way.
//
// In the order the targets came in, so a report reads the same twice.
func homeInstructionFiles(targets []*agentTarget) []homeInstructionFile {
	var out []homeInstructionFile
	at := map[string]int{}
	for _, target := range targets {
		path := target.homeInstructions
		if path == "" {
			continue
		}
		rules := len(target.accountFiles) > 0
		if i, seen := at[path]; seen {
			out[i].accountRules = out[i].accountRules && rules
			continue
		}
		at[path] = len(out)
		out = append(out, homeInstructionFile{path: path, accountRules: rules})
	}
	return out
}

// homeSection is the section `init` writes into a home.
//
// Rendered rather than shipped as it is, for one sentence.  Three agents get
// deny rules in this home that refuse their file tools wherever they are
// working; pi has nowhere to put them, so the same list is compiled into the
// extension `init-project` installs, and Antigravity has no file that would
// refuse a file tool anything.  Telling either that its file tools are refused
// everywhere would be telling it about a rule that is not there.
//
// It names no path this install decides, the rules it explains being rendered
// into each agent's own config from protectedpaths.go.
func homeSection(accountRules bool) (string, error) {
	body, err := renderData("agent/instructions.home.md.snippet",
		struct{ AccountRules bool }{AccountRules: accountRules})
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}
