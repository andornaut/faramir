package enrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// The same for an enrolment, whose section is the one that travels in the
// project's own repository.
func TestEnrolFailsOnAnInstructionsFileItCannotBringUpToDate(t *testing.T) {
	tree := t.TempDir()
	path := filepath.Join(tree, "AGENTS.md")
	before := "# Project\n\n" + agentcfg.SectionEnd + "\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{opts: Options{Dir: tree}, uid: hostfs.Keep, gid: hostfs.Keep}

	err := run.instructions()

	if err == nil {
		t.Fatal("an enrolment that could not update the instructions reported success")
	}
	if !strings.Contains(err.Error(), "enrol") {
		t.Errorf("the error does not name the command to run again: %v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was rewritten:\n%s", body)
	}
}

// Claude Code reads CLAUDE.md and not AGENTS.md, so a tree whose own file is an
// AGENTS.md gets a CLAUDE.md of its own. Without it the agent that most needs
// the credentials section is the one agent an enrolled tree tells nothing.
func TestAnEnrolmentWritesClaudeCodeItsOwnFileBesideTheTreesAgentsFile(t *testing.T) {
	tree := t.TempDir()
	agents := filepath.Join(tree, "AGENTS.md")
	if err := os.WriteFile(agents, []byte("# Project\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    Options{Dir: tree},
		uid:     hostfs.Keep,
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
		body, err := os.ReadFile(filepath.Join(tree, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(body), agentcfg.SectionBegin) {
			t.Errorf("%s carries no credentials section:\n%s", name, body)
		}
	}
}

// An operator keeping one file for every agent links CLAUDE.md at AGENTS.md.
// The two are then one file carrying one section, rather than a pair refused as
// two writes with one survivor: every instructions file in a tree gets the same
// section, so the link loses nothing.
func TestALinkedClaudeFileIsOneFileWrittenOnce(t *testing.T) {
	tree := t.TempDir()
	agents := filepath.Join(tree, "AGENTS.md")
	link := filepath.Join(tree, "CLAUDE.md")
	if err := os.WriteFile(agents, []byte("# Project\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(agents, link); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    Options{Dir: tree},
		uid:     os.Getuid(),
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	// Asked before the write, and the write itself: the pair has to pass both.
	if err := run.refuseUnwritableFiles(); err != nil {
		t.Fatalf("the linked pair was refused before anything was written: %v", err)
	}
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(agents)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(body), agentcfg.SectionBegin); got != 1 {
		t.Errorf("the file carries %d credentials sections, want 1:\n%s", got, body)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced with a regular file, so the operator's " +
			"one file for every agent became two")
	}
}
