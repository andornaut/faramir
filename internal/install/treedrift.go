package install

import (
	"bytes"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// What an enrolled tree still carries of what `init-project` wrote into it.
//
// The files are the hook, the plugin that calls it and the MCP registration,
// and between them they are what makes an agent in that tree run its commands
// through the broker.  A tree is shared with the client group, and unlink and
// rename are permissions on the directory, so a brokered command can replace
// one of these whatever mode the file itself carries; the sticky bit sharing
// sets narrows that and does not close it.  A hand edit reaches the same place.
//
// So this reports and a human decides, as the account-wide drift check does.
// Warned rather than failed, because a tree enrolled with --hook=false is a
// tree that legitimately carries none of this and the record cannot tell the
// two apart.
func diagnoseTreeConfig(report *DoctorReport, opts DoctorOptions) {
	trees := readEnrolled(opts.ConfigDir)
	if len(trees) == 0 {
		report.add("tree config", StatusOK, "no tree is recorded as enrolled")
		return
	}
	checked := 0
	var drifted, unread []string
	for _, tree := range trees {
		// A tree that is gone is diagnoseAgentRules' finding, not this one.
		if !exists(tree.Dir) {
			continue
		}
		checked++
		for _, name := range tree.Agents {
			target, known := agentTargets[name]
			if !known {
				continue
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
	}
	sort.Strings(drifted)
	sort.Strings(unread)

	if len(drifted) == 0 && len(unread) == 0 {
		report.add("tree config", StatusOK, "%d enrolled tree(s) carry what "+
			"`faramir init-project` wrote", checked)
		return
	}
	if len(unread) > 0 {
		report.unasked("tree config", len(unread), "could not read %s, so what "+
			"they carry was not compared with what `faramir init-project` writes",
			strings.Join(unread, ", "))
	}
	if len(drifted) > 0 {
		report.add("tree config", StatusWarn, "%d file(s) an enrolment wrote no "+
			"longer carry what it writes, so nothing those agents run in that tree "+
			"is redacted: %s. Re-run `sudo faramir init-project` in the tree. A tree "+
			"enrolled with --hook=false reads the same way and is not a fault",
			len(drifted), strings.Join(drifted, ", "))
	}
}

// carriesWhatWeWrite reports whether a file on disk still carries what an
// enrolment puts in it.
//
// A merged file is asked the question a merge answers: if merging faramir's
// keys into what is there changes nothing, then what is there already has them,
// whatever else the project added beside them.  A file that is faramir's own is
// compared as bytes, that being the whole of what it should hold.
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
	merged, err := mergeJSON(onDisk, ours)
	if err != nil {
		return false, err
	}
	return bytes.Equal(merged, onDisk), nil
}

// What `init` and `init-project` would refuse to write, asked without writing.
//
// Both commands now stop rather than take over a file faramir edits but does
// not own, or follow a link out of the tree. That is the right answer at the
// time, and it is a poor way to learn: the operator finds out when a run they
// wanted stops. `doctor` exists to answer this before it costs anybody a run.
//
// Warned, not failed. Nothing is unguarded: the deny rules and the hook are
// whatever the last successful run left, and what this names is a file the next
// run will not be able to update.
func diagnoseEditableFiles(report *DoctorReport, opts DoctorOptions) {
	if opts.AgentUser == "" {
		report.unasked("agent file ownership", 1, "the agent account is not "+
			"named, so who owns the files an install edits was not asked: pass "+
			"--agent-user, or run through sudo so SUDO_USER carries it")
		return
	}
	home, err := agentHomeFor(opts.AgentUser)
	if err != nil || home == "" {
		report.unasked("agent file ownership", 1, "could not read %s's home, so "+
			"who owns the files an install edits was not asked", opts.AgentUser)
		return
	}
	uid, err := lookupUser(opts.AgentUser)
	if err != nil {
		report.unasked("agent file ownership", 1, "could not resolve %s: %v",
			opts.AgentUser, err)
		return
	}
	reportEditableFiles(report, home, uid, opts)
}

// reportEditableFiles is diagnoseEditableFiles against a home and an operator
// already resolved, so a test can put one somewhere other than a real account's
// rather than skipping wherever the developer has a ~/.claude of their own.
func reportEditableFiles(report *DoctorReport, home string, uid int, opts DoctorOptions) {
	fs := fsys{}
	var targets []*agentTarget
	for _, name := range agentNames() {
		targets = append(targets, agentTargets[name])
	}
	refused := refuseUnwritable(fs, home, uid, "", homeEditedPaths(targets))
	for _, tree := range readEnrolled(opts.ConfigDir) {
		if !exists(tree.Dir) {
			continue
		}
		treeUID := uid
		if tree.AgentUser != opts.AgentUser {
			// The tree was enrolled for somebody else, and this is their file to
			// own rather than the account doctor was pointed at.
			if other, err := lookupUser(tree.AgentUser); err == nil {
				treeUID = other
			}
		}
		// Every path this tree's enrolment writes, asked in one call: two of them
		// resolving to one file is refuseUnwritable's to find, and it finds it
		// only among the paths it is given together.
		var paths []string
		// The tree's own instructions file, which every enrolment writes whatever
		// it was enrolled for, and which no target names.
		if rel, err := filepath.Rel(tree.Dir, treeInstructionsFile(tree.Dir)); err == nil {
			paths = append(paths, rel)
		}
		for _, name := range tree.Agents {
			target, known := agentTargets[name]
			if !known {
				continue
			}
			paths = append(paths, editedPaths(target, true, target.treeInstructions.path)...)
		}
		refused = append(refused, refuseUnwritable(fs, tree.Dir, treeUID, tree.Dir, paths)...)
	}
	sort.Strings(refused)
	if len(refused) == 0 {
		report.add("agent file ownership", StatusOK, "every file an install edits "+
			"is the operator's, or is not there yet")
		return
	}
	report.add("agent file ownership", StatusWarn, "%d file(s) `faramir init` or "+
		"`faramir init-project` would refuse to write, so the next run stops rather "+
		"than taking one over or writing one of them twice: %s",
		len(refused), strings.Join(refused, "; "))
}
