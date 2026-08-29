package install

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
)

// What an enrolled tree still carries of what `init-project` wrote into it,
// which is Claude Code's routing hook and nothing else: every other agent is
// guarded from a home, and routing costs a permission on this one alone.
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
func diagnoseTreeConfig(report *DoctorReport, opts DoctorOptions) {
	trees, why := readEnrolledWhy(opts.ConfigDir)
	// A record that could not be read is not one naming nothing: reporting it
	// as an empty enrolment tells an operator with a host of enrolled trees
	// that they have none.
	if why != "" {
		report.addf("tree config", StatusFailed, "%s, so which trees are enrolled "+
			"is unknown and none were examined. Restore the record, or re-run "+
			"`sudo faramir init-project` in each tree to rewrite it", why)
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
		if !exists(tree.Dir) {
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
		instructions := []sectionTarget{{path: treeInstructionsFile(tree.Dir)}}
		heads := map[string]string{}
		for _, name := range tree.Agents {
			target, known := agentTargets[name]
			if !known {
				continue
			}
			if rules := target.treeInstructions; rules.path != "" {
				path := filepath.Join(tree.Dir, rules.path)
				instructions = append(instructions, sectionTarget{path: path})
				heads[path] = rules.head
			}
			for _, file := range target.files {
				path := filepath.Join(tree.Dir, file.path)
				switch carries, err := carriesWhatWeWrite(target, file, path, opts.ConfigDir); {
				case err != nil:
					unread = append(unread, path)
				case !carries:
					drifted = append(drifted, path)
				}
			}
		}
		for _, file := range oneSectionPerFile(instructions) {
			body, err := os.ReadFile(file.path)
			switch {
			case err != nil && os.IsNotExist(err):
				prose = append(prose, file.path)
			case err != nil:
				unread = append(unread, file.path)
			case !strings.Contains(string(body), sectionBegin),
				heads[file.path] != "" && !strings.HasPrefix(string(body), heads[file.path]):
				prose = append(prose, file.path)
			}
		}
	}
	sort.Strings(drifted)
	sort.Strings(prose)
	sort.Strings(unread)
	sort.Strings(unguarded)

	if len(unguarded) > 0 {
		report.addf("tree config", StatusWarn, "%d enrolled tree(s) registered no "+
			"agent, so they are shared with the client group and nothing they run "+
			"is redacted: %s. Enrol one with `sudo faramir init-project --agent "+
			"NAME` in the tree, or take the enrolment back",
			len(unguarded), strings.Join(unguarded, ", "))
	}

	if len(drifted) == 0 && len(prose) == 0 && len(unread) == 0 {
		if len(unguarded) > 0 {
			return
		}
		report.addf("tree config", StatusOK, "%d enrolled tree(s) carry what "+
			"`faramir init-project` wrote", checked)
		return
	}
	if len(prose) > 0 {
		report.addf("tree config", StatusWarn, "%d instructions file(s) an "+
			"enrolment wrote no longer carry the credentials section or the "+
			"frontmatter that loads them, so an agent refused a path is not told "+
			"the route: %s. Re-run `sudo faramir init-project` in the tree",
			len(prose), strings.Join(prose, ", "))
	}
	if len(unread) > 0 {
		report.unaskedf("tree config", len(unread), "could not read %s, so what "+
			"they carry was not compared with what `faramir init-project` writes",
			strings.Join(unread, ", "))
	}
	if len(drifted) > 0 {
		// What drifted is not said, only that something did: this compares a merge
		// rather than reading the file, so it knows the file no longer carries
		// everything an enrolment writes and not which part. Saying "nothing is
		// redacted" was wrong whenever the hook was intact and only the deny rules
		// had gone, which is what declaring a blocked path leaves behind.
		report.addf("tree config", StatusWarn, "%d file(s) an enrolment wrote no "+
			"longer carry all of it, so the hook that redacts, the rules that refuse "+
			"a path, or the registration that reaches the broker is missing from "+
			"them: %s. Re-run `sudo faramir init-project` in the tree, which writes "+
			"all three again",
			len(drifted), strings.Join(drifted, ", "))
	}
}

// carriesWhatWeWrite reports whether a file on disk still carries what an
// enrolment puts in it. A merged file is asked the question a merge answers:
// if merging faramir's keys changes nothing, what is there already has them. A
// file that is faramir's own is compared as bytes.
func carriesWhatWeWrite(target *agentTarget, file agentFile, path, configDir string) (bool, error) {
	onDisk, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	ours, err := assetFor(target, file, configDir)
	if err != nil {
		return false, err
	}
	if !file.merge {
		return bytes.Equal(onDisk, ours), nil
	}
	// The same record the write uses: a rule this run would take out is a
	// difference between the file and what a render produces, which is what
	// drift means.
	merged, err := mergeJSON(onDisk, ours, readWrittenRules(configDir)[path])
	if err != nil {
		return false, err
	}
	if bytes.Equal(merged, onDisk) {
		return true, nil
	}
	// Not in the merge's normal form is not drift: a hand edit that appended a
	// key leaves the file unsorted, and warning that the hook or the rules are
	// missing over key order sends an operator hunting for a loss that did not
	// happen. Parsed and compared as documents instead.
	var mergedDoc, onDiskDoc any
	if err := json.Unmarshal(merged, &mergedDoc); err != nil {
		return false, err
	}
	// The on-disk bytes already survived the merge above, so this cannot fail;
	// treated as drift rather than an error if it somehow does.
	if err := json.Unmarshal(onDisk, &onDiskDoc); err != nil {
		return false, nil //nolint:nilerr // unparseable is drift, not a fault to stop on
	}
	return reflect.DeepEqual(mergedDoc, onDiskDoc), nil
}

// diagnoseEditableFiles asks what `init` and `init-project` would refuse to
// write, without writing. Both stop rather than take over a file faramir edits
// and does not own, or follow a link out of the tree, and the operator would
// otherwise find that out when a run they wanted stops.
//
// Warned, not failed: the deny rules and the hook are whatever the last
// successful run left, and what this names is a file the next run cannot
// update.
func diagnoseEditableFiles(report *DoctorReport, opts DoctorOptions) {
	if opts.AgentUser == "" {
		report.unaskedf("agent file ownership", 1, "the agent account is not "+
			"named, so who owns the files an install edits was not asked: run "+
			"through sudo so SUDO_USER carries it, or record the account with "+
			"`faramir init --agent-user`")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unaskedf("agent file ownership", 1, "could not read %s's home, so "+
			"who owns the files an install edits was not asked", opts.AgentUser)
		return
	}
	uid, err := lookupUser(opts.AgentUser)
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
func reportEditableFiles(report *DoctorReport, home string, uid int, opts DoctorOptions) {
	fs := fsys{}
	// The agents `init` would configure in this home, not every one faramir
	// knows: a refusal about a file an install would never write is a false
	// alarm, an operator's own prose-file links across uninstalled agents the
	// usual shape of one.
	targets, err := resolveAgents(nil, scopeHome, home)
	if err != nil {
		targets = nil
	}
	refused := refuseUnwritable(fs, home, uid, "", homeEditedPaths(targets))
	for _, tree := range readEnrolled(opts.ConfigDir) {
		if !exists(tree.Dir) {
			continue
		}
		treeUID := uid
		if tree.AgentUser != opts.AgentUser {
			// The tree was enrolled for somebody else, and this is their file to own
			// rather than the account doctor was pointed at. One that no longer
			// resolves is a question that cannot be put, not the current account's
			// files to judge.
			other, err := lookupUser(tree.AgentUser)
			if err != nil {
				report.unaskedf("agent file ownership", 1, "%s is enrolled for %q, "+
					"which does not resolve, so who owns its files was not asked",
					tree.Dir, tree.AgentUser)
				continue
			}
			treeUID = other
		}
		// Every path this tree's enrolment writes, asked in one call: two of them
		// resolving to one file is refuseUnwritable's to find, and only among the
		// paths it is given together.
		var paths []string
		// The tree's own instructions file, which every enrolment writes and no
		// target names, and then each agent's own.
		instructions := []sectionTarget{{path: treeInstructionsFile(tree.Dir)}}
		for _, name := range tree.Agents {
			target, known := agentTargets[name]
			if !known {
				continue
			}
			paths = append(paths, editedPaths(target, true, "")...)
			if rules := target.treeInstructions; rules.path != "" {
				instructions = append(instructions,
					sectionTarget{path: filepath.Join(tree.Dir, rules.path)})
			}
		}
		// Deduplicated as the enrolment writes them, so a tree whose CLAUDE.md is
		// a link to its AGENTS.md is not reported as a file written twice that the
		// enrolment writes once.
		for _, file := range oneSectionPerFile(instructions) {
			if rel, err := filepath.Rel(tree.Dir, file.path); err == nil {
				paths = append(paths, rel)
			}
		}
		refused = append(refused, refuseUnwritable(fs, tree.Dir, treeUID, tree.Dir, paths)...)
	}
	sort.Strings(refused)
	if len(refused) == 0 {
		report.addf("agent file ownership", StatusOK, "every file an install edits "+
			"is the operator's, or is not there yet")
		return
	}
	report.addf("agent file ownership", StatusWarn, "%d file(s) `faramir init` or "+
		"`faramir init-project` would refuse to write, so the next run stops rather "+
		"than taking one over or writing one of them twice: %s",
		len(refused), strings.Join(refused, "; "))
}
