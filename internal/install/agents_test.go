package install

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

// Naming no agent enrols Claude Code, so a command written before --agent
// existed keeps doing what it did.
func TestAgentsDefaultToClaude(t *testing.T) {
	got, err := resolveAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "claude" {
		t.Errorf("resolveAgents(nil) = %v, want claude alone", got)
	}
}

// An unknown name stops the run rather than being skipped. A run that enrolled
// nothing and mentioned it in a line nobody read leaves an operator believing a
// project is covered when it is not.
func TestUnknownAgentIsRefused(t *testing.T) {
	if _, err := resolveAgents([]string{"claude", "nosuchagent"}); err == nil {
		t.Error("an unknown agent was accepted")
	}
}

// Repeats collapse: enrolling the same agent twice writes its files twice and
// reports the second as unchanged, which reads as a failure to write.
func TestAgentsDeduplicate(t *testing.T) {
	got, err := resolveAgents([]string{"gemini", "claude", "gemini"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, target := range got {
		names = append(names, target.name)
	}
	if !reflect.DeepEqual(names, []string{"gemini", "claude"}) {
		t.Errorf("names = %v, want [gemini claude] in the order given", names)
	}
}

// What enrolling costs differs by agent, and the warning a run prints has to be
// the truth for the agent it just enrolled. On Claude Code a rewritten command
// matches no permission rule and the hook must approve it; on Gemini CLI there
// is no approval to give, so the prompts are untouched.
func TestOnlyClaudeAutoApprovesBash(t *testing.T) {
	if !agentTargets["claude"].autoApprovesBash {
		t.Error("claude does not record that it auto-approves Bash")
	}
	if agentTargets["gemini"].autoApprovesBash {
		t.Error("gemini claims to auto-approve Bash; it has no allow to return")
	}
}

// Every descriptor names assets that exist. A typo here is an enrolment that
// fails after the tree's ownership has already been changed.
func TestAgentAssetsExist(t *testing.T) {
	for name, target := range agentTargets {
		if len(target.files) == 0 {
			t.Errorf("%s writes nothing", name)
		}
		for _, file := range target.files {
			if _, err := readAsset(file.asset); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// Detection reports and never enrols. A directory left behind by trying an
// agent once is not a decision to enrol it, and on some agents enrolling trades
// away every Bash prompt in the project.
func TestDetectionFindsAgentDirectoriesWithoutEnrolling(t *testing.T) {
	dir := t.TempDir()
	if got := detectedAgents(dir); len(got) != 0 {
		t.Errorf("detected %v in an empty tree", got)
	}
	if err := os.Mkdir(filepath.Join(dir, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := detectedAgents(dir); !reflect.DeepEqual(got, []string{"gemini"}) {
		t.Errorf("detectedAgents = %v, want [gemini]", got)
	}
	// Still not enrolled: detection feeds a report, and resolveAgents is what
	// decides, from what the operator asked for.
	targets, err := resolveAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.name == "gemini" {
			t.Error("a .gemini directory enrolled gemini by itself")
		}
	}
}
