package enrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

func TestReenrolmentCombinesPreviouslyEnabledHarnesses(t *testing.T) {
	tree, configDir := t.TempDir(), t.TempDir()
	if err := agentcfg.RecordEnrolment(configDir, agentcfg.EnrolledTree{
		Dir: tree, Agents: []string{"codex", "pi"},
	}); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts: Options{Dir: tree, ConfigDir: configDir}, uid: hostfs.Keep, gid: hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}
	for range 2 {
		if err := run.instructions(); err != nil {
			t.Fatal(err)
		}
	}
	body, err := os.ReadFile(filepath.Join(tree, "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"- claude", "- codex", "- pi", "Never route around a refusal"} {
		if strings.Count(string(body), want) != 1 {
			t.Errorf("shared instructions must contain %q once", want)
		}
	}
	if strings.Count(string(body), agentcfg.SectionBegin) != 1 || len(run.instructionsFiles()) != 1 {
		t.Fatal("one project file must receive one managed section")
	}
	if got := run.enabledTargets(); len(got) != 3 {
		t.Fatalf("enabled harnesses = %d, want 3", len(got))
	}
	// Preflight uses the same union when configuring hooks and recording agents.
	targets := run.enabledTargets()
	names := make([]string, 0, len(targets))
	for _, target := range targets {
		names = append(names, target.Name)
	}
	if err := agentcfg.RecordEnrolment(configDir, agentcfg.EnrolledTree{Dir: tree, Agents: names}); err != nil {
		t.Fatal(err)
	}
	records := agentcfg.ReadEnrolled(configDir)
	if len(records) != 1 || len(records[0].Agents) != 3 {
		t.Fatalf("project enrollment was split or lost a harness: %+v", records)
	}
}

func TestUnreadableEnrollmentRecordDoesNotReplaceSharedInstructions(t *testing.T) {
	tree, configDir := t.TempDir(), t.TempDir()
	path := filepath.Join(tree, "AGENTS.md")
	const before = "User text and existing managed instructions\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(agentcfg.EnrolledPath(configDir), []byte("invalid json"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &project{opts: Options{Dir: tree, ConfigDir: configDir}, uid: hostfs.Keep, gid: hostfs.Keep}
	if err := run.instructions(); err == nil {
		t.Fatal("unknown enrolled harnesses must stop the write")
	}
	if after, err := os.ReadFile(path); err != nil || string(after) != before {
		t.Fatal("existing instructions changed with an unreadable enrollment record")
	}
}

func TestLegacyInstructionMigrationPreservesUserTextAndManagedSections(t *testing.T) {
	for _, legacy := range []string{"CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", ".claude/CLAUDE.md", ".agents/rules/faramir.md"} {
		t.Run(legacy, func(t *testing.T) {
			tree := t.TempDir()
			path := filepath.Join(tree, legacy)
			if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
				t.Fatal(err)
			}
			before := "@AGENTS.md\n\nUser instructions\n" + agentcfg.SectionBegin + "\nLegacy credentials\n" + agentcfg.SectionEnd + "\n"
			if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
				t.Fatal(err)
			}
			run := &project{
				opts: Options{Dir: tree}, uid: hostfs.Keep, gid: hostfs.Keep,
				targets: []*agentcfg.Target{agentcfg.Targets["claude"], agentcfg.Targets["codex"]},
			}
			if err := run.instructions(); err != nil {
				t.Fatal(err)
			}
			after, err := os.ReadFile(path)
			if err != nil || string(after) != before {
				t.Fatal("legacy user text or managed protections were changed")
			}
			canonical, err := os.ReadFile(filepath.Join(tree, "AGENTS.md"))
			if err != nil || !strings.Contains(string(canonical), "Never route around a refusal") {
				t.Fatal("canonical managed protections were not written")
			}
			if !strings.Contains(strings.Join(run.report.Warnings, "\n"), path) {
				t.Fatal("operator migration was not reported")
			}
		})
	}
}

func TestBuiltInHarnessesUseOnlyCanonicalProjectInstructions(t *testing.T) {
	for _, name := range agentcfg.Known() {
		target := agentcfg.Targets[name]
		if path := target.TreeInstructions.Path; path != "" && path != "AGENTS.md" {
			t.Errorf("%s has alternate project target %s", name, path)
		}
	}
	for name, want := range map[string]string{
		"claude": ".claude/CLAUDE.md", "codex": ".codex/AGENTS.md", "agy": ".gemini/GEMINI.md",
	} {
		if got := agentcfg.Targets[name].HomeInstructions; got != want {
			t.Errorf("%s global target = %s, want %s", name, got, want)
		}
	}
}

func TestMigrationWarnsAboutAncestorOverridesButPreservesGlobalInstructions(t *testing.T) {
	home := t.TempDir()
	homeAlias := filepath.Join(t.TempDir(), "home")
	if err := os.Symlink(home, homeAlias); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o750); err != nil {
		t.Fatal(err)
	}
	global := filepath.Join(home, ".claude", "CLAUDE.md")
	ancestor := filepath.Join(home, "CLAUDE.local.md")
	for _, path := range []string{global, ancestor} {
		if err := os.WriteFile(path, []byte("User policy\n"), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	tree := filepath.Join(home, "project")
	if err := os.Mkdir(tree, 0o750); err != nil {
		t.Fatal(err)
	}
	// The canonical name may be an existing alias of a legacy instruction file.
	legacy := filepath.Join(tree, "CLAUDE.md")
	if err := os.WriteFile(legacy, []byte("Project text\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(legacy, filepath.Join(tree, "AGENTS.md")); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts: Options{Dir: tree}, uid: hostfs.Keep, gid: hostfs.Keep, agentHome: homeAlias,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	for _, want := range []string{ancestor, legacy, "regular file", "complete user text and managed credentials section"} {
		if !strings.Contains(warnings, want) {
			t.Errorf("migration warning omits %q", want)
		}
	}
	if strings.Contains(warnings, global) {
		t.Fatal("native global instructions were reported as a project override")
	}
	if body, err := os.ReadFile(global); err != nil || string(body) != "User policy\n" {
		t.Fatal("global instructions were changed")
	}
	if body, err := os.ReadFile(legacy); err != nil || !strings.Contains(string(body), "Project text") || strings.Count(string(body), agentcfg.SectionBegin) != 1 {
		t.Fatal("aliased project content was lost or received competing sections")
	}
}
