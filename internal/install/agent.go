package install

import (
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
		r.step("agent instructions", false, "no coding agent found, so no credentials "+
			"section was written")
		return nil
	}
	// Against the install layout: what an account file interpolates is the paths
	// this install decided on.
	asLayout := func(file agentFile) ([]byte, error) { return render(file.asset, r.layout) }

	changed := false
	var written []string
	for _, target := range targets {
		// 0700: these sit in the operator's home, which no other account has
		// business entering.
		made, paths, err := writeAgentFiles(r.fs, r.operatorHome,
			r.operatorUID, r.operatorGID, 0o700, asLayout, target.accountFiles)
		written = append(written, paths...)
		if err != nil {
			return err
		}
		changed = changed || made
	}
	r.step("agent config", changed, strings.Join(written, ", "))
	return r.agentInstructions(targets)
}

// agentInstructions writes the account-wide credentials section into each
// enrolled agent's home instructions file.
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
	section, err := homeSection()
	if err != nil {
		return err
	}
	changed := false
	var written []string
	for _, target := range targets {
		if target.homeInstructions == "" {
			continue
		}
		path := filepath.Join(r.operatorHome, target.homeInstructions)
		// The operator's own group, not keep, and never re-owned: same reason as
		// the rule files above.  A .pi/agent or .kilocode/rules that does not
		// exist yet would otherwise be created operator:root.
		if _, err := r.fs.ensureDir(
			filepath.Dir(path), 0o700, r.operatorUID, r.operatorGID, false); err != nil {
			return err
		}
		made, err := r.fs.sectionFile(path, section, r.operatorUID, r.operatorGID)
		if leftAlone(err) {
			// Not fatal: the rules are written and hold either way, and what is
			// missing is the paragraph explaining them.
			r.warn("%s", sectionWarning(err, path, "`sudo faramir init`"))
			written = append(written, path+" (left as it is; see the warning)")
			continue
		}
		if err != nil {
			return err
		}
		changed = changed || made
		written = append(written, path)
	}
	r.step("agent instructions", changed, strings.Join(written, ", "))
	return nil
}

// homeSection is the section `init` writes into a home.  Shipped as it is: it
// names no path this install decides, the rules it explains being written into
// each agent's own config from protectedpaths.go.
func homeSection() (string, error) {
	body, err := readAsset("agent/instructions.home.md.snippet")
	if err != nil {
		return "", err
	}
	return strings.TrimRight(string(body), "\n") + "\n", nil
}
