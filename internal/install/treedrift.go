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
