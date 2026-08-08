package install

import (
	"fmt"
	"os"
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
	if !r.opts.AgentConfig {
		r.skip("agent config", "not requested")
		return nil
	}
	settingsDir := filepath.Join(r.operatorHome, ".claude")
	// Only created, never re-owned: an existing .claude is the account's own,
	// and chmodding it here would rewrite whatever it had.
	if _, err := r.fs.ensureDir(settingsDir, 0o700, r.operatorUID, keep, false); err != nil {
		return err
	}
	settings := filepath.Join(settingsDir, "settings.json")
	// Kept if it exists: a settings file is the operator's to edit, and
	// overwriting one loses hooks and permissions this project knows nothing
	// about.
	dst := settings
	detail := settings
	if exists(settings) {
		dst = settings + ".dist"
		detail = fmt.Sprintf("keeping %s; wrote %s beside it to merge", settings, dst)
	}
	data, err := readAsset("agent/claude/settings.json")
	if err != nil {
		return err
	}
	changed, err := r.fs.writeFile(dst, data, 0o600, r.operatorUID, keep)
	if err != nil {
		return err
	}
	r.step("agent config", changed, detail)

	// An install from before the hook moved has it in the home, where it covers
	// every project including the ones that never opted in and get nothing back
	// for it.  Reported rather than edited: that file is the operator's.
	if body, err := os.ReadFile(settings); err == nil && strings.Contains(string(body), "faramir-guard") {
		r.warn("%s registers faramir-guard for every project, which auto-approves "+
			"Bash in all of them. The hook is per project now: remove the hooks "+
			"block there and add it to the projects that should have it", settings)
	}
	return nil
}
