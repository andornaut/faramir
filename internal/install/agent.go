package install

import (
	"path/filepath"
	"strings"
)

// stepAgentConfig registers the broker with the account the coding agent runs
// as, which is the operator's own.
//
// Two scopes, because the two things faramir ships for an agent do not have the
// same cost, and only the cheaper one is installed here.
//
// The Read deny rules go in the operator's home: they refuse to open key
// material wherever the agent is working, and they take nothing away, so there
// is no reason to make a project opt into them.
//
// The PreToolUse hook goes in a project and is not installed by this.  It
// rewrites every Bash command so the output can be redacted, and a rewritten
// command matches no Bash permission rule, so the hook approves what its deny
// list did not refuse.  For that project, Bash is auto-approved.  That is worth
// it where managed credentials are in play and is not worth it everywhere,
// which is why it is a per-project decision.
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
			// Only created, never re-owned: an existing agent directory is the
			// account's own, and chmodding it here would rewrite what it had.
			if _, err := r.fs.ensureDir(filepath.Dir(path), 0o700, r.operatorUID, keep, false); err != nil {
				return err
			}
			data, err := render(file.asset, r.layout)
			if err != nil {
				return err
			}
			// Merged rather than overwritten: this file is the operator's to
			// edit and holds rules faramir knows nothing about.  Only the keys
			// faramir writes are touched.
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
