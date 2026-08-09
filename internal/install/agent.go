package install

import (
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
	if len(r.opts.Agents) == 0 {
		r.skip("agent config", "no --agent named")
		return nil
	}
	targets, err := resolveAgents(r.opts.Agents)
	if err != nil {
		return err
	}
	changed := false
	var written []string
	for _, target := range targets {
		for _, file := range target.accountFiles {
			path := filepath.Join(r.operatorHome, file.path)
			// Only created, never re-owned: the directory is the account's.
			if _, err := r.fs.ensureDir(filepath.Dir(path), 0o700, r.operatorUID, keep, false); err != nil {
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
			made, err := write(path, data, file.mode, r.operatorUID, keep)
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
