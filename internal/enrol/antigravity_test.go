package enrol

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// A tree carries one set of files for both halves, so detecting the sibling in
// a tree an enrolment already covered is not finding an agent nothing redacts.
// Warning there would send an operator to enrol a second agent over the same
// bytes.
func TestEnrollingOneHalfDoesNotReportTheOtherAsUncovered(t *testing.T) {
	tree := t.TempDir()
	opts := Options{Dir: tree, ConfigDir: t.TempDir()}
	first := &project{opts: opts, uid: hostfs.Keep, gid: hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]}}
	if err := first.agentConfig(); err != nil {
		t.Fatal(err)
	}

	// The same tree again, so the files are there to be detected.
	second := &project{opts: opts, uid: hostfs.Keep, gid: hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]}}
	if err := second.agentConfig(); err != nil {
		t.Fatal(err)
	}
	for _, warning := range second.report.Warnings {
		if strings.Contains(warning, "was not enrolled") {
			t.Errorf("the sibling was reported as an agent nothing covers, over the "+
				"files this enrolment wrote: %s", warning)
		}
	}
	// The hook is account-wide now, so an enrolment writes the tree no files at
	// all: what it leaves is the prose. Asserted so that a tree file reappearing
	// is noticed rather than assumed.
	if len(agentcfg.Targets["agy"].Files) != 0 {
		t.Errorf("the enrolment writes %d file(s) into a tree, where the guard is "+
			"installed for the account", len(agentcfg.Targets["agy"].Files))
	}
}

// The CLI reads a tree's own instructions file as well as its rules directory,
// so enrolling it must leave both. The rules file is what covers a tree whose
// own file is named something this agent does not read.
func TestTheCLIGetsBothATreeFileAndARulesFile(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    Options{Dir: tree, ConfigDir: t.TempDir()},
		uid:     hostfs.Keep,
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]},
	}
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AGENTS.md", agentcfg.Targets["agy"].TreeInstructions.Path} {
		body, err := os.ReadFile(filepath.Join(tree, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(body), agentcfg.SectionBegin) {
			t.Errorf("%s carries no credentials section:\n%s", name, body)
		}
	}
}
