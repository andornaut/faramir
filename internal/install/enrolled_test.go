package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// An enrolment is the one thing that knows a tree was enrolled and for what.
// Keyed by directory, so re-enrolling says the later thing rather than both.
func TestRecordingAnEnrolmentIsKeyedByTree(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "project")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, agents := range [][]string{{"claude"}, {"gemini", "pi"}} {
		if err := recordEnrolment(dir, EnrolledTree{
			Dir: tree, Operator: "op", Agents: agents,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := readEnrolled(dir)
	if len(got) != 1 {
		t.Fatalf("recorded %d entries for one tree, want 1: %+v", len(got), got)
	}
	if !slices.Equal(got[0].Agents, []string{"gemini", "pi"}) {
		t.Errorf("agents = %v, want the later enrolment's", got[0].Agents)
	}
}

// What doctor reads it for: which agents some tree relies on, which a home
// cannot show, and which entries name a tree that is no longer there.
func TestEnrolledAgentsSeparatesWhatIsThereFromWhatIsGone(t *testing.T) {
	dir := t.TempDir()
	here := filepath.Join(dir, "here")
	if err := os.MkdirAll(here, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tree := range []EnrolledTree{
		{Dir: here, Operator: "op", Agents: []string{"gemini"}},
		{Dir: filepath.Join(dir, "gone"), Operator: "op", Agents: []string{"claude"}},
	} {
		if err := recordEnrolment(dir, tree); err != nil {
			t.Fatal(err)
		}
	}
	agents, stale := enrolledAgents(dir)
	if !slices.Equal(agents, []string{"gemini"}) {
		t.Errorf("agents = %v, want only the tree that is still there", agents)
	}
	if len(stale) != 1 || stale[0].Agents[0] != "claude" {
		t.Errorf("stale = %+v, want the entry whose tree is gone", stale)
	}
}

// A record of convenience: an install is not refused an examination because
// this file will not parse, and nothing here is a boundary.
func TestAnUnreadableRecordIsEmptyRatherThanFatal(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(enrolledPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := readEnrolled(dir); got != nil {
		t.Errorf("read %+v from a file that does not parse, want nothing", got)
	}
	agents, stale := enrolledAgents(dir)
	if agents != nil || stale != nil {
		t.Errorf("got %v and %+v, want nothing from an unreadable record", agents, stale)
	}
}

// A tree enrolled for an agent that leaves no trace in the home is the case a
// home alone cannot see, and the one this record exists for.
func TestAnEnrolledAgentIsAFaultEvenWithNothingInTheHome(t *testing.T) {
	var report DoctorReport
	reportAgentRules(&report, t.TempDir(), []string{"gemini"})

	var found bool
	for _, finding := range report.Findings {
		if finding.Status == StatusFailed && strings.Contains(finding.Detail, "gemini") {
			found = true
		}
	}
	if !found {
		t.Errorf("an agent a tree is enrolled for was not reported: %+v", report.Findings)
	}
	if !report.Failed {
		t.Error("the report does not fail for an enrolled agent with no rules")
	}
}
