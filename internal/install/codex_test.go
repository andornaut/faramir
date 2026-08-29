package install

import (
	"encoding/json"
	"strings"
	"testing"
)

// Codex's enrolment is Claude Code's shape written into a different file, and
// the two halves are one path under two roots. What these cover is the ways
// that goes wrong silently: the two halves rendered from one asset and the
// account approving every command on the machine, a registration in a dialect
// the guard does not answer in, and a hook the agent never reaches.

// codexHook is the hook registration Codex reads, as the agent parses it.
type codexHook struct {
	Hooks struct {
		PreToolUse []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"PreToolUse"`
	} `json:"hooks"`
}

// renderCodexHook renders one of the two halves and reads back the command it
// registers.
func renderCodexHook(t *testing.T, file agentFile) (codexHook, string) {
	t.Helper()
	body, err := assetFor(agentTargets["codex"], file, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	var doc codexHook
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("%s is not JSON the agent can read: %v\n%s", file.path, err, body)
	}
	if len(doc.Hooks.PreToolUse) != 1 || len(doc.Hooks.PreToolUse[0].Hooks) != 1 {
		t.Fatalf("%s registers %d matcher group(s), so what runs is not one guard:\n%s",
			file.path, len(doc.Hooks.PreToolUse), body)
	}
	return doc, doc.Hooks.PreToolUse[0].Hooks[0].Command
}

// The two halves differ in one flag and nothing else. Without --deny-only the
// account-wide hook approves every command the deny list does not name, in
// every directory, which is the trade an enrolment exists to take one tree at a
// time; with it in the tree's hook, nothing is ever routed and no output is
// redacted.
func TestTheTwoHalvesOfACodexEnrolmentDifferByTheApproval(t *testing.T) {
	target := agentTargets["codex"]
	if len(target.accountFiles) != 1 || len(target.files) != 1 {
		t.Fatalf("codex writes %d account file(s) and %d tree file(s), want one each",
			len(target.accountFiles), len(target.files))
	}
	account, accountCommand := renderCodexHook(t, target.accountFiles[0])
	tree, treeCommand := renderCodexHook(t, target.files[0])

	if !strings.Contains(accountCommand, "--deny-only") {
		t.Errorf("the account-wide hook approves what it does not refuse, so every "+
			"command on this machine is approved: %q", accountCommand)
	}
	if strings.Contains(treeCommand, "--deny-only") {
		t.Errorf("the tree's hook refuses and routes nothing, so an enrolment "+
			"redacts no output: %q", treeCommand)
	}
	for _, tc := range []struct {
		path    string
		command string
	}{{target.accountFiles[0].path, accountCommand}, {target.files[0].path, treeCommand}} {
		if !strings.Contains(tc.command, "--host codex") {
			t.Errorf("%s does not name the dialect, so the reply is in a shape Codex "+
				"ignores: %q", tc.path, tc.command)
		}
		if !strings.HasPrefix(tc.command, DefaultBinDir+"/faramir guard") {
			t.Errorf("%s does not run the installed guard: %q", tc.path, tc.command)
		}
	}

	// Every tool, on both. An empty reply is a call left alone, so answering for
	// a tool that runs nothing costs nothing, and a matcher naming Bash leaves
	// apply_patch -- the whole of how Codex writes a file -- in front of nothing.
	for _, tc := range []struct {
		path string
		doc  codexHook
	}{{target.accountFiles[0].path, account}, {target.files[0].path, tree}} {
		if got := tc.doc.Hooks.PreToolUse[0].Matcher; got != "*" {
			t.Errorf("%s matches %q rather than every tool, so the tool Codex writes "+
				"files with is unguarded", tc.path, got)
		}
	}
}

// The two halves are the same relative path under different roots, which is
// what makes them two assets rather than one. A tree's copy is the operator's
// machine rather than the repository's: it names the binary this install put in
// place, so it belongs in git's ignores.
func TestCodexWritesOnePathUnderTwoRoots(t *testing.T) {
	target := agentTargets["codex"]
	if target.accountFiles[0].path != target.files[0].path {
		t.Errorf("the two halves are written to %q and %q; Codex reads one name at "+
			"both scopes", target.accountFiles[0].path, target.files[0].path)
	}
	if target.accountFiles[0].asset == target.files[0].asset {
		t.Error("both halves render the same asset, so one of them carries the " +
			"other's approval")
	}
	if !target.files[0].local {
		t.Error("the tree's hook is not marked local, so an enrolment offers to " +
			"commit this machine's paths")
	}
	if target.accountFiles[0].local {
		t.Error("an account file is marked local; nothing in a home is committed")
	}
	// Both are merged: the account's is the operator's own hooks file, and a tree
	// may carry hooks that have nothing to do with faramir.
	for _, file := range []agentFile{target.accountFiles[0], target.files[0]} {
		if !file.merge {
			t.Errorf("%s replaces the file rather than merging into it, so an "+
				"operator's own hooks are lost", file.path)
		}
	}
}

// Two conditions faramir cannot meet on this agent's behalf, and both fail
// quietly: an untrusted hook is skipped without a word, and a sandboxed Codex
// is refused the broker socket, which withholds every command's output rather
// than redacting it. Neither is something a later run can check, so each has to
// be said. At both scopes: the account-wide hook and a tree's are inert under
// either.
func TestCodexSaysWhatItCannotCheck(t *testing.T) {
	target := agentTargets["codex"]
	for _, tc := range []struct {
		scope string
		note  string
	}{{"a tree", target.note}, {"the account", target.accountNote}} {
		if tc.note == "" {
			t.Errorf("%s is enrolled without a word about either condition", tc.scope)
			continue
		}
		if !strings.Contains(tc.note, "trust") {
			t.Errorf("the note for %s does not say the hook has to be trusted: %q", tc.scope, tc.note)
		}
		if !strings.Contains(tc.note, "sandbox") {
			t.Errorf("the note for %s does not say Codex must run without its sandbox: %q",
				tc.scope, tc.note)
		}
	}
	// And it stands on every enrolment, not only the one that wrote the files:
	// what it describes is what this tree is rather than what a run just did.
	if !target.noteStands {
		t.Error("the note is warned about only on the run that writes, so an operator " +
			"enrolling a second tree is never told")
	}
	// Codex is the one agent with a condition of this kind. Another would need
	// its own reason, not this one's.
	for _, name := range knownAgents() {
		if name != "codex" && agentTargets[name].accountNote != "" {
			t.Errorf("%s carries an account-wide note, which is printed on every "+
				"`init` whether or not it changed anything", name)
		}
	}
}

// Codex reads AGENTS.md and not CLAUDE.md, the mirror image of Claude Code. A
// tree whose own file is a CLAUDE.md would otherwise leave this agent nothing:
// the rules still hold there, and what it would be missing is what they refuse
// and why.
func TestCodexIsGivenAFileItReads(t *testing.T) {
	target := agentTargets["codex"]
	if got := target.treeInstructions.path; got != "AGENTS.md" {
		t.Errorf("tree instructions = %q, want AGENTS.md", got)
	}
	if got := target.homeInstructions; got != ".codex/AGENTS.md" {
		t.Errorf("home instructions = %q, want .codex/AGENTS.md", got)
	}
}
