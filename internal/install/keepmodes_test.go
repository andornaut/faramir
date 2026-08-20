package install

import (
	"path/filepath"
	"slices"
	"testing"
)

// everyTarget is every agent this can enrol, in the order resolveAgents returns
// them.
func everyTarget(t *testing.T) []*agentTarget {
	t.Helper()
	targets, err := resolveAgents(knownAgents(), scopeTree, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(targets) == 0 {
		t.Fatal("no agents to enrol, so every loop below runs zero times")
	}
	return targets
}

// The share widens every file in the tree to group-writable, and these are the
// files that must not become one: .claude/settings.local.json names the PreToolUse
// hook, the plugins are JavaScript the agent loads, and the MCP registrations
// name the binary each of them execs. A path missing from Keep is one the walk
// widens, and nothing afterwards narrows it again.
//
// Derived from the targets rather than listed here, so an agent file added
// later is covered without anybody remembering this.
func TestEveryFileAnEnrolmentWritesIsKeptFromTheShare(t *testing.T) {
	dir := t.TempDir()
	run := &project{opts: ProjectOptions{Dir: dir}, targets: everyTarget(t)}

	keep := run.keepModes()

	for _, target := range run.targets {
		for _, file := range target.files {
			if !slices.Contains(keep, file.path) {
				t.Errorf("%s writes %s and the share would widen it: keep = %v",
					target.name, file.path, keep)
			}
		}
	}
}

// The instructions files as well as the configuration. They carry no hook, but
// they are what the agent is told about credentials, and a shared tree that
// leaves them group-writable lets anything in the client group rewrite the
// policy the agent reads.
func TestTheInstructionsFilesAreKeptFromTheShareToo(t *testing.T) {
	dir := t.TempDir()
	run := &project{opts: ProjectOptions{Dir: dir}, targets: everyTarget(t)}

	keep := run.keepModes()

	for _, file := range run.instructionsFiles() {
		rel, err := filepath.Rel(dir, file.path)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Contains(keep, rel) {
			t.Errorf("the section is written into %s and the share would widen it: "+
				"keep = %v", rel, keep)
		}
	}
}

// Relative to the tree, which is how sharetree matches them: an absolute path
// in this list matches nothing in the walk and reads as covered.
func TestWhatIsKeptIsNamedTheWaySharetreeMatchesIt(t *testing.T) {
	run := &project{opts: ProjectOptions{Dir: t.TempDir()}, targets: everyTarget(t)}

	for _, path := range run.keepModes() {
		if filepath.IsAbs(path) || path != filepath.Clean(path) {
			t.Errorf("%q is not a cleaned path relative to the tree", path)
		}
	}
}

// An enrolment that configured no agent still writes the tree's own
// instructions, so that file is still kept.
func TestATreeWithNoAgentStillKeepsItsInstructionsFile(t *testing.T) {
	run := &project{opts: ProjectOptions{Dir: t.TempDir()}}

	keep := run.keepModes()

	if len(keep) != 1 || keep[0] != agentInstructionFiles[0] {
		t.Errorf("keep = %v, want just %s", keep, agentInstructionFiles[0])
	}
}
