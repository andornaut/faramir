package install

import (
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

// An agent that gets no rule file gets its refusals somewhere else, and where
// that is has to be a file the agent actually reads. The Antigravity IDE is the
// case these cover: its permission lists are its own state, so there is no rule
// file to write, and what holds instead is a hook, account-wide for what it
// reads and per tree for what it runs. Every claim below is about those
// arriving, and about the enrolment saying what is still conditional.

// A file two agents read is named once when a run refuses it: an operator gets
// a list of what to fix, and one file listed twice reads as two. No shipped
// pair shares a file, so the targets here are built rather than looked up.
func TestAFileTwoAgentsReadIsNamedOnce(t *testing.T) {
	const shared = "AGENTS.md"
	first := &agentcfg.Target{Name: "first", HomeInstructions: shared}
	second := &agentcfg.Target{Name: "second", HomeInstructions: shared}

	paths := agentcfg.HomeEditedPaths([]*agentcfg.Target{first, second})

	if n := slices.Index(paths, shared); n < 0 {
		t.Fatalf("paths = %v, want the file they share", paths)
	}
	if n := len(paths); n != 1 {
		t.Errorf("paths = %v, want the shared file named once", paths)
	}
}

// The claim a shared file makes is the weaker of the two, whichever agent was
// named first. An agent told it is refused everywhere, and finding it is not,
// has no reason to believe the next claim; one told to assume nothing stops it
// has been told the truth either way.
func TestTheClaimInASharedHomeFileIsTheWeakerOne(t *testing.T) {
	const path = "AGENTS.md"
	guarded := &agentcfg.Target{
		Name:             "guarded",
		HomeInstructions: path,
		AccountFiles:     []agentcfg.File{{Path: ".config/guarded.json"}},
	}
	bare := &agentcfg.Target{Name: "bare", HomeInstructions: path}

	for _, order := range [][]*agentcfg.Target{{guarded, bare}, {bare, guarded}} {
		files := homeInstructionFiles(order)
		if len(files) != 1 {
			t.Fatalf("%s then %s: %d files, want the one they share",
				order[0].Name, order[1].Name, len(files))
		}
		if files[0].path != path {
			t.Errorf("%s then %s: the shared file is %q, want %q",
				order[0].Name, order[1].Name, files[0].path, path)
		}
	}
	// And one agent alone still names it once.
	files := homeInstructionFiles([]*agentcfg.Target{guarded})
	if len(files) != 1 || files[0].path != path {
		t.Errorf("homeInstructionFiles = %+v, want the one file", files)
	}
}

// Every agent has something account-wide, which is what makes a tree nobody
// enrolled covered: the deny rules an agent enforces itself, or faramir's own
// guard reached through a hook, a plugin or an extension installed in a home.
//
// This is the invariant the whole arrangement rests on. An agent added without
// one is an agent whose refusals reach only the trees somebody enrolled, and
// nothing else here would say so.
func TestEveryAgentIsCoveredAccountWide(t *testing.T) {
	for _, name := range agentcfg.Known() {
		if len(agentcfg.Targets[name].AccountFiles) == 0 {
			t.Errorf("%s writes nothing into a home, so a tree nobody enrolled has "+
				"none of its refusals", name)
		}
	}
}

// Nothing is auto-approved on its behalf: there is no allow to return, and a
// report claiming the Bash trade was taken would be naming a cost this agent
// does not pay.
func TestAnAgentWithNoHookTakesNothingAway(t *testing.T) {
	target := agentcfg.Targets["antigravity"]
	if target.AutoApprovesBash {
		t.Error("antigravity claims to auto-approve Bash, having no hook that could")
	}
	// What it writes account-wide is a hook, not a permission rule: its lists are
	// the IDE's own state, and an install that wrote one would be writing a file
	// the agent does not read.
	for _, file := range target.AccountFiles {
		if !strings.HasSuffix(file.Path, "hooks.json") {
			t.Errorf("antigravity writes %s account-wide, which is not a file it "+
				"reads: its permission lists are the IDE's own state", file.Path)
		}
	}
}
