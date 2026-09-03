package doctor

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// What an enrolled tree still carries of what `enrol` wrote into it,
// which is Claude Code's routing hook and nothing else: every other agent is
// guarded from a home, and only on this one does routing suppress a permission
// prompt.
//
// A tree is shared with the client group, and unlink and rename are permissions
// on the directory, so a brokered command can replace one of these whatever
// mode the file carries; the sticky bit narrows that and does not close it. A
// hand edit reaches the same place.
//
// So this reports and a human decides. Warned rather than failed: the record
// says what was enrolled and when rather than what the tree is now, so a
// checkout that moved, a branch that never carried these files and a hand edit
// all read the same way from here.
func diagnoseTreeConfig(report *Report, opts Options) {
	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	// A record that could not be read is not one naming nothing: reporting it
	// as an empty enrolment tells an operator with a host of enrolled trees
	// that they have none.
	//
	// A permission denial is not that. The record is 0600 root, so an
	// unprivileged run cannot read it and there is nothing wrong with the file:
	// reported as not asked, the way every other root-only check here is, rather
	// than as a failure advising a repair.
	switch {
	case errors.Is(err, os.ErrPermission):
		report.unaskedf("tree config", 1, "the record of enrolled trees is "+
			"readable only by the operator, so which trees are enrolled was not checked "+
			"and none were examined. Run doctor as root")
		return
	case err != nil:
		report.addf("tree config", StatusFailed, "%s, so which trees are enrolled "+
			"is unknown and none were examined. Restore the record, or re-run "+
			"`sudo faramir enrol` in each tree to rewrite it", err)
		return
	}
	if len(trees) == 0 {
		report.addf("tree config", StatusOK, "no tree is recorded as enrolled")
		return
	}
	checked := 0
	var drifted, prose, unread, unguarded []string
	for _, tree := range trees {
		// A tree that is gone is diagnoseAgentRules' finding, not this one.
		if !hostfs.Exists(tree.Dir) {
			continue
		}
		checked++
		// An enrolment that registered no agent: the tree is shared with the
		// client group and nothing in it is redacted, which is the consequence a
		// drifted file has. Reported for as long as it holds, the one line saying
		// so at enrolment having scrolled past.
		if len(tree.Agents) == 0 {
			unguarded = append(unguarded, tree.Dir)
		}
		// The instruction files, which every enrolment writes: the credentials
		// section in the tree's own file and each agent's, and the frontmatter
		// that makes a rules file load at all. What they carry is the guidance
		// the rules lean on, and for the Antigravity family the rules file plus
		// the account hook is the whole tree enrolment. Deduplicated as the
		// enrolment writes them, so a linked CLAUDE.md is one file asked once.
		instructions := []agentcfg.SectionTarget{{Path: agentcfg.TreeInstructionsFile(tree.Dir)}}
		heads := map[string]string{}
		for _, name := range tree.Agents {
			target, known := agentcfg.Targets[name]
			if !known {
				continue
			}
			if rules := target.TreeInstructions; rules.Path != "" {
				path := filepath.Join(tree.Dir, rules.Path)
				instructions = append(instructions, agentcfg.SectionTarget{Path: path})
				heads[path] = rules.Head
			}
			for _, file := range target.Files {
				path := filepath.Join(tree.Dir, file.Path)
				switch carries, err := carriesWhatWeWrite(target, file, path, opts.ConfigDir); {
				case err != nil:
					unread = append(unread, path)
				case !carries:
					drifted = append(drifted, path)
				}
			}
		}
		for _, file := range agentcfg.OneSectionPerFile(instructions) {
			body, err := os.ReadFile(file.Path)
			switch {
			case err != nil && os.IsNotExist(err):
				prose = append(prose, file.Path)
			case err != nil:
				unread = append(unread, file.Path)
			case !strings.Contains(string(body), agentcfg.SectionBegin),
				heads[file.Path] != "" && !strings.HasPrefix(string(body), heads[file.Path]):
				prose = append(prose, file.Path)
			}
		}
	}
	sort.Strings(drifted)
	sort.Strings(prose)
	sort.Strings(unread)
	sort.Strings(unguarded)

	if len(unguarded) > 0 {
		report.addf("tree config", StatusWarn, "%d enrolled tree(s) registered "+
			"no agent, so they are shared with the client group and nothing they run is "+
			"redacted: %s. Enrol one with `sudo faramir enrol --agent NAME` in the tree, "+
			"or undo the enrolment",
			len(unguarded), strings.Join(unguarded, ", "))
	}

	if len(drifted) == 0 && len(prose) == 0 && len(unread) == 0 {
		if len(unguarded) > 0 {
			return
		}
		report.addf("tree config", StatusOK, "%d enrolled tree(s) carry what "+
			"`faramir enrol` wrote", checked)
		return
	}
	if len(prose) > 0 {
		report.addf("tree config", StatusWarn, "%d instructions file(s) an "+
			"enrolment wrote no longer carry the credentials section or the frontmatter "+
			"that loads it, so an agent refused a path is not told the route: %s. Re-run "+
			"`sudo faramir enrol` in the tree",
			len(prose), strings.Join(prose, ", "))
	}
	if len(unread) > 0 {
		report.unaskedf("tree config", len(unread), "could not read %s, so they "+
			"were not compared with what `faramir enrol` writes",
			strings.Join(unread, ", "))
	}
	if len(drifted) > 0 {
		// What drifted is not said, only that something did: this compares a merge
		// rather than reading the file, so it knows the file no longer carries
		// everything an enrolment writes and not which part. Saying "nothing is
		// redacted" was wrong whenever the hook was intact and only the deny rules
		// had gone, which is what declaring a blocked path leaves behind.
		report.addf("tree config", StatusWarn, "%d file(s) an enrolment wrote "+
			"no longer carry all of it, so the hook that redacts, the rules that refuse a "+
			"path, or the registration that reaches the broker is missing: %s. Re-run "+
			"`sudo faramir enrol` in the tree, which writes all three again",
			len(drifted), strings.Join(drifted, ", "))
	}
}

// carriesWhatWeWrite reports whether a file on disk still carries what an
// enrolment puts in it. A merged file is asked the question a merge answers:
// if merging faramir's keys changes nothing, what is there already has them. A
// file that is faramir's own is compared as bytes.
func carriesWhatWeWrite(target *agentcfg.Target, file agentcfg.File, path, configDir string) (bool, error) {
	onDisk, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	ours, err := agentcfg.AssetFor(target, file, configDir)
	if err != nil {
		return false, err
	}
	if !file.Merge {
		return bytes.Equal(onDisk, ours), nil
	}
	// The same record the write uses: a rule this run would take out is a
	// difference between the file and what a render produces, which is what
	// drift means.
	merged, err := agentcfg.MergeJSON(onDisk, ours, agentcfg.ReadWrittenRules(configDir)[path])
	if err != nil {
		return false, err
	}
	return sameDocument(merged, onDisk), nil
}

// sameDocument compares two JSON renderings as documents. Not in the merge's
// normal form is not drift: a hand edit that appended a key leaves the file
// unsorted, and warning that the hook or the rules are missing over key order
// sends an operator hunting for a loss that did not happen.
func sameDocument(a, b []byte) bool {
	if bytes.Equal(a, b) {
		return true
	}
	var aDoc, bDoc any
	if json.Unmarshal(a, &aDoc) != nil || json.Unmarshal(b, &bDoc) != nil {
		return false
	}
	return reflect.DeepEqual(aDoc, bDoc)
}

// diagnoseTreeModes: the files an enrolment writes keep their own mode and
// their directory the sticky bit. Group-writable is what the enforcing files
// must never be, the client group holding the executor; sticky is what keeps a
// brokered command from renaming one aside. Both are the precondition for the
// substitution the tree check above catches only after the fact.
func diagnoseTreeModes(report *Report, opts Options) {
	trees, err := agentcfg.ReadEnrolledWhy(opts.ConfigDir)
	// The record's own state is tree config's finding, reported once.
	if err != nil || len(trees) == 0 {
		return
	}
	examined := 0
	var writable, unsticky []string
	stickySeen := map[string]bool{}
	for _, tree := range trees {
		if !hostfs.Exists(tree.Dir) {
			continue
		}
		examined++
		var enforcing, kept []string
		kept = append(kept, treeInstructionsRel(tree.Dir)...)
		for _, name := range tree.Agents {
			target, known := agentcfg.Targets[name]
			if !known {
				continue
			}
			enforcing = append(enforcing, agentcfg.EditedPaths(target, true, "")...)
			if rules := target.TreeInstructions; rules.Path != "" {
				kept = append(kept, rules.Path)
			}
		}
		// The enforcing files carry the hook and the rules, and the enrolment
		// writes them 0640: group write there is the client group rewriting what
		// refuses it. An instructions file keeps whatever mode the operator's
		// own file had, so only its directory is asked about.
		for _, rel := range enforcing {
			path := filepath.Join(tree.Dir, rel)
			info, err := os.Lstat(path)
			if err != nil {
				continue
			}
			if info.Mode().Perm()&0o022 != 0 {
				writable = append(writable, fmt.Sprintf("%s (%04o)", path, info.Mode().Perm()))
			}
		}
		for _, rel := range append(append([]string{}, enforcing...), kept...) {
			dir := filepath.Dir(filepath.Clean(rel))
			if dir == "." {
				// The tree root is deliberately not sticky; see sharetree.
				continue
			}
			parent := filepath.Join(tree.Dir, dir)
			if stickySeen[parent] {
				continue
			}
			stickySeen[parent] = true
			info, err := os.Stat(parent)
			if err != nil {
				continue
			}
			if info.Mode()&os.ModeSticky == 0 {
				unsticky = append(unsticky, parent)
			}
		}
	}
	sort.Strings(writable)
	sort.Strings(unsticky)
	switch {
	case len(writable) > 0:
		report.addf("tree modes", StatusFailed, "%d enrolment-written file(s) are "+
			"group- or world-writable, so the accounts the tree is shared with can "+
			"rewrite what refuses them: %s. `chmod go-w` each, or re-run `sudo "+
			"faramir enrol` in the tree", len(writable), strings.Join(writable, "; "))
	case len(unsticky) > 0:
		report.addf("tree modes", StatusWarn, "%d directory(ies) holding an "+
			"enrolment-written file lost the sticky bit, so a brokered command may "+
			"rename the file aside whatever its mode: %s. `chmod +t` each",
			len(unsticky), strings.Join(unsticky, "; "))
	case examined > 0:
		report.addf("tree modes", StatusOK, "%d enrolled tree(s) keep their agent "+
			"files closed to group write, in sticky directories", examined)
	}
}

// treeInstructionsRel is the tree's own instructions file as a relative path,
// for the checks that collect paths that way.
func treeInstructionsRel(dir string) []string {
	if rel, err := filepath.Rel(dir, agentcfg.TreeInstructionsFile(dir)); err == nil {
		return []string{rel}
	}
	return nil
}

// diagnoseEditableFiles asks what `init` and `enrol` would refuse to
// write, without writing. Both stop rather than take over a file faramir edits
// and does not own, or follow a link out of the tree, and the operator would
// otherwise find that out when a run they wanted stops.
//
// Warned, not failed: the deny rules and the hook are whatever the last
// successful run left, and what this names is a file the next run cannot
// update.
func diagnoseEditableFiles(report *Report, opts Options) {
	if opts.AgentUser == "" {
		report.unaskedf("agent file ownership", 1, "the agent account is not "+
			"named, so who owns the files an install edits was not checked. Run doctor "+
			"through sudo (SUDO_USER names the account), or record it with `sudo faramir init "+
			"--agent-user`")
		return
	}
	home, err := agentcfg.HomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent file ownership", 1, "could not read %s's home, "+
			"so who owns the files an install edits was not checked", opts.AgentUser)
		return
	}
	uid, err := hostfs.LookupUser(opts.AgentUser)
	if err != nil {
		report.unaskedf("agent file ownership", 1, "could not resolve %s: %v",
			opts.AgentUser, err)
		return
	}
	reportEditableFiles(report, home, uid, opts)
}

// reportEditableFiles is diagnoseEditableFiles against a home and an operator
// already resolved, so a test can put one somewhere other than a real
// account's.
func reportEditableFiles(report *Report, home string, uid int, opts Options) {
	fs := hostfs.FS{}
	// The agents `init` would configure in this home, not every one faramir
	// knows: a refusal about a file an install would never write is a false
	// alarm, an operator's own prose-file links across uninstalled agents the
	// usual shape of one.
	targets, err := agentcfg.Resolve(nil, agentcfg.ScopeHome, home, home)
	if err != nil {
		targets = nil
	}
	refused := agentcfg.RefuseUnwritable(fs, home, uid, "", agentcfg.HomeEditedPaths(targets))
	for _, tree := range agentcfg.ReadEnrolled(opts.ConfigDir) {
		if !hostfs.Exists(tree.Dir) {
			continue
		}
		treeUID := uid
		if tree.AgentUser != opts.AgentUser {
			// The tree was enrolled for somebody else, and this is their file to own
			// rather than the account doctor was pointed at. One that no longer
			// resolves is a question that cannot be put, not the current account's
			// files to judge.
			other, err := hostfs.LookupUser(tree.AgentUser)
			if err != nil {
				report.unaskedf("agent file ownership", 1, "%s is enrolled for "+
					"%q, which does not resolve, so who owns its files was not checked",
					tree.Dir, tree.AgentUser)
				continue
			}
			treeUID = other
		}
		// Every path this tree's enrolment writes, asked in one call: two of them
		// resolving to one file is agentcfg.RefuseUnwritable's to find, and only among the
		// paths it is given together.
		var paths []string
		// The tree's own instructions file, which every enrolment writes and no
		// target names, and then each agent's own.
		instructions := []agentcfg.SectionTarget{{Path: agentcfg.TreeInstructionsFile(tree.Dir)}}
		for _, name := range tree.Agents {
			target, known := agentcfg.Targets[name]
			if !known {
				continue
			}
			paths = append(paths, agentcfg.EditedPaths(target, true, "")...)
			if rules := target.TreeInstructions; rules.Path != "" {
				instructions = append(instructions,
					agentcfg.SectionTarget{Path: filepath.Join(tree.Dir, rules.Path)})
			}
		}
		// Deduplicated as the enrolment writes them, so a tree whose CLAUDE.md is
		// a link to its AGENTS.md is not reported as a file written twice that the
		// enrolment writes once.
		for _, file := range agentcfg.OneSectionPerFile(instructions) {
			if rel, err := filepath.Rel(tree.Dir, file.Path); err == nil {
				paths = append(paths, rel)
			}
		}
		refused = append(refused, agentcfg.RefuseUnwritable(fs, tree.Dir, treeUID, tree.Dir, paths)...)
	}
	sort.Strings(refused)
	if len(refused) == 0 {
		report.addf("agent file ownership", StatusOK, "every file an install edits "+
			"is the operator's, or is not there yet")
		return
	}
	report.addf("agent file ownership", StatusWarn, "%d file(s) `faramir init` "+
		"or `faramir enrol` would refuse to write, so the next run stops instead of "+
		"taking one over or writing one of them twice: %s",
		len(refused), strings.Join(refused, "; "))
}
