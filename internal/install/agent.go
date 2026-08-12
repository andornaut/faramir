package install

import (
	"fmt"
	"path/filepath"
	"strings"
)

// stepAgentConfig registers the broker with the operator's own account, which is
// what the coding agent runs as.
//
// Only the Read deny rules go here: they refuse to open key material wherever
// the agent is working and take nothing away.  The PreToolUse hook is
// per-project, because a rewritten command matches no Bash permission rule, so
// registering it auto-approves Bash for that project.
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
	targets, err := resolveAgents(r.opts.Agents, scopeHome, r.operatorHome)
	if err != nil {
		return err
	}
	if len(targets) == 0 {
		// Not an error and not a silent pass: nothing was written, and the reason
		// is a home with no agent in it rather than a step that did its job.
		r.step("agent config", false, fmt.Sprintf(
			"no coding agent found in %s, so no deny rules were written. "+
				"`faramir init --agent NAME` writes them anyway (%s)",
			r.operatorHome, strings.Join(knownAgents(), ", ")))
		return nil
	}
	changed := false
	var written []string
	for _, target := range targets {
		for _, file := range target.accountFiles {
			path := filepath.Join(r.operatorHome, file.path)
			// Only created, never re-owned: the directory is the account's.  With the
			// operator's own group, not keep: this runs as root, so a ~/.config that
			// does not exist yet would be created operator:root and break every other
			// tool that keeps state there.  preflight refuses to create ConfigDir's
			// parent for the same reason.
			if _, err := r.fs.ensureDir(
				filepath.Dir(path), 0o700, r.operatorUID, r.operatorGID, false); err != nil {
				return err
			}
			data, err := render(file.asset, r.layout)
			if err != nil {
				return err
			}
			// Merged, not overwritten: the file is the operator's to edit, and
			// only the keys faramir writes are touched.
			write := r.fs.writeFile
			if file.merge {
				write = r.fs.mergeFile
			}
			made, err := write(path, data, file.mode, r.operatorUID, r.operatorGID)
			if err != nil {
				return err
			}
			changed = changed || made
			written = append(written, path)
		}
	}
	r.step("agent config", changed, strings.Join(written, ", "))
	return nil
}
