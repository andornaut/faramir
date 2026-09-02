package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
	"github.com/andornaut/faramir/internal/layouttest"
	"github.com/andornaut/faramir/internal/steps"
)

// agentStep runs the account-level agent step against a home the test built,
// and returns what it reported. Dry run: what is asserted is which agents it
// decided on, and writing into a temporary home to find that out would only
// test the filesystem.
func agentStep(t *testing.T, home string, agents ...string) steps.Step {
	t.Helper()
	run := &runner{
		opts:         Options{Agents: agents, DryRun: true},
		layout:       testLayout(),
		fs:           hostfs.FS{DryRun: true},
		operatorUID:  hostfs.Keep,
		operatorGID:  hostfs.Keep,
		operatorHome: home,
	}
	// The ordering a run uses: preconditions resolve the targets and ask of
	// every file the question the step then answers.
	if err := run.refuseUnwritableAgentFiles(); err != nil {
		t.Fatal(err)
	}
	if err := run.stepAgentConfig(); err != nil {
		t.Fatal(err)
	}
	for _, step := range run.report.Steps {
		if step.Name == "agent config" {
			return step
		}
	}
	t.Fatal("the step reported nothing")
	return steps.Step{}
}

// A home with no coding agent in it gets no rules, and is told so. The other
// direction -- writing configuration into a home for five agents the operator
// does not run -- is not this command's to do.
func TestInitWritesNoRulesForAHomeWithNoAgent(t *testing.T) {
	got := agentStep(t, t.TempDir())

	if got.Changed {
		t.Error("an empty home was reported as changed")
	}
	// The state and the way out of it: an operator who does want an agent
	// configured ahead of installing it has to be told how to say so.
	for _, want := range []string{"no coding agent", "--agent"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not say %q: %s", want, got.Detail)
		}
	}
}

// The agents that are there get their rules, and the ones that are not do not.
func TestInitWritesRulesForTheAgentsInTheHome(t *testing.T) {
	home := t.TempDir()
	layouttest.Touch(t, home, ".config/opencode/opencode.json")

	got := agentStep(t, home)

	if !strings.Contains(got.Detail, ".config/opencode/opencode.json") {
		t.Errorf("opencode's rules were not written: %s", got.Detail)
	}
	if strings.Contains(got.Detail, ".claude") {
		t.Errorf("claude's rules were written into a home with no claude: %s", got.Detail)
	}
}

// Naming an agent writes its rules whether or not it is installed, which is
// what lets an operator set one up before installing it.
func TestInitWritesRulesForANamedAgentThatIsAbsent(t *testing.T) {
	got := agentStep(t, t.TempDir(), "claude")

	if !strings.Contains(got.Detail, ".claude/settings.json") {
		t.Errorf("a named agent's rules were not written: %s", got.Detail)
	}
}

// auto and a name compose here as they do everywhere: what is installed, plus
// the one asked for.
func TestInitUnionsAutoWithANamedAgent(t *testing.T) {
	home := t.TempDir()
	layouttest.Touch(t, home, ".config/opencode/opencode.json")

	got := agentStep(t, home, agentcfg.Auto, "claude")

	for _, want := range []string{".config/opencode/opencode.json", ".claude/settings.json"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not name %s: %s", want, got.Detail)
		}
	}
}

// faramir's own rule file is evidence too, which is what makes a second run
// refresh what the first wrote rather than deciding the agent has gone: an
// operator who removed ~/.claude but kept the settings file still has rules
// there, and they should stay current.
func TestInitKeepsMaintainingRulesItAlreadyWrote(t *testing.T) {
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(
		filepath.Join(home, ".claude", "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	got := agentStep(t, home)

	if !strings.Contains(got.Detail, ".claude/settings.json") {
		t.Errorf("a home faramir had already written to was passed over: %s", got.Detail)
	}
}
