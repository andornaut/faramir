package install

import (
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/denyrules"
)

// A declared command is the words, taken literally, with any run of whitespace
// between them. Not a pattern the operator writes: a language here would be a
// second thing to get wrong in a file that decides what an agent may run, and
// both failures are silent.
func TestADeclaredCommandIsTheWords(t *testing.T) {
	// The path prefix is part of the words: a command is the same command
	// wherever the program it names is installed.
	head := denyrules.CommandPosition + denyrules.CommandPathPrefix
	for command, want := range map[string]string{
		"op read":       head + `op\s+read\b`,
		"sops -d":       head + `sops\s+-d\b`,
		"pass show":     head + `pass\s+show\b`,
		"terraform":     head + `terraform\b`,
		"op  read":      head + `op\s+read\b`,
		"a.b c":         head + `a\.b\s+c\b`,
		"gh auth token": head + `gh\s+auth\s+token\b`,
	} {
		if got := agentcfg.BlockedCommandRule(command); got != want {
			t.Errorf("%q rendered %q, want %q", command, got, want)
		}
	}
}

// An entry is in force when the add reports it, not after the next install.
// Both files an entry feeds are rendered by the steps a `block` run applies:
// the agents' own rule files, and the one the command guard reads. Without the
// second, `block add --command` reported changed and the agent's shell could
// still run the command, a command entry having no file-tool half at all.
func TestABlockRunRendersBothEntryPoints(t *testing.T) {
	var run runner
	var agents, patterns bool
	for _, step := range run.BlockedSteps() {
		switch step.name {
		case labelAgentConfig:
			agents = true
		case "deny patterns":
			patterns = true
		}
	}
	if !agents {
		t.Error("a block run does not render the agents' rule files")
	}
	if !patterns {
		t.Error("a block run does not render the file the command guard reads")
	}
	// A link is a subject in both too.
	patterns = false
	for _, step := range run.LinkSteps() {
		if step.name == "deny patterns" {
			patterns = true
		}
	}
	if !patterns {
		t.Error("a link run does not render the file the command guard reads")
	}
}

// A command entry has no path, so nothing stats one: the warning said "` is not
// there`" with an empty path where the path goes, once per command entry on
// every run, which is how a warnings channel stops being read.
func TestACommandEntryWarnsAboutItselfRatherThanAnEmptyPath(t *testing.T) {
	var report Report
	blockedWarnings(&report, config.BlockedPath{Command: "op read"}, nil)
	if len(report.Warnings) != 1 {
		t.Fatalf("warnings = %v, want one", report.Warnings)
	}
	got := report.Warnings[0]
	if strings.Contains(got, "is not there") {
		t.Errorf("a command entry was stat'ed as a path: %s", got)
	}
	if !strings.Contains(got, "op read") {
		t.Errorf("the warning does not name the command: %s", got)
	}
}

// Two commands are two entries. They share an empty path and an empty name, so
// an identity that reads only those two fields folds every command an operator
// declares into whichever one they declared first, and `block add --command`
// reports the rest as already blocked while writing none of them.
func TestTwoCommandsAreTwoEntries(t *testing.T) {
	asked := []config.BlockedPath{
		{Command: "op read"},
		{Command: "pass show"},
		{Command: "op read"}, // named twice in one call
		{Command: "vault read"},
	}
	entries, added := foldBlocked(nil, asked)
	if want := []bool{true, true, false, true}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v", added, want)
	}
	want := []string{"op read", "pass show", "vault read"}
	if len(entries) != len(want) {
		t.Fatalf("the set holds %d entries, want %d: %+v", len(entries), len(want), entries)
	}
	for i, blocks := range want {
		if got := entries[i].Command; got != blocks {
			t.Errorf("entry %d is %q, want %q", i, got, blocks)
		}
	}
}

// A command and a path are not one entry even where they read alike.
func TestACommandAndAPathAreNotOneEntry(t *testing.T) {
	entries, added := foldBlocked(
		[]config.BlockedPath{{Path: "/srv/luks.key"}},
		[]config.BlockedPath{{Command: "op read"}, {Command: "op inject"}},
	)
	if want := []bool{true, true}; !slices.Equal(added, want) {
		t.Errorf("added = %v, want %v: a command and a path that read alike "+
			"render different rules", added, want)
	}
	if len(entries) != 3 {
		t.Fatalf("the set holds %d entries, want 3: %+v", len(entries), entries)
	}
}
