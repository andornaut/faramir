package install

import (
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

// An agent that gets no rule file gets its refusals somewhere else, and the
// enrolment has to say what is still conditional. The Antigravity IDE is the
// case: its permission lists are its own state, so what holds instead is a
// hook, and a home file it shares with an agent that does have rules.

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
