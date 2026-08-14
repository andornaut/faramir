package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// enrolledTree is a tree carrying the evidence each named agent leaves in one,
// which is what an entry is bounded by.
func enrolledTree(t *testing.T, dir string, agents ...string) string {
	t.Helper()
	tree := filepath.Join(dir, "project")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, name := range agents {
		for _, marker := range agentTargets[name].detect {
			if err := os.MkdirAll(filepath.Join(tree, marker), 0o755); err != nil {
				t.Fatal(err)
			}
		}
	}
	return tree
}

// An enrolment is the one thing that knows a tree was enrolled and for what.
// One entry per directory, and enrolling one agent by name does not drop the
// others: their hook and MCP registration are still in the tree, and an entry
// dropped here is a tree doctor stops checking those agents' account-wide rules
// for, which nothing would report.
func TestRecordingAnEnrolmentKeepsTheAgentsATreeStillCarries(t *testing.T) {
	dir := t.TempDir()
	tree := enrolledTree(t, dir, "claude", "opencode", "pi")

	for _, agents := range [][]string{{"claude"}, {"opencode", "pi"}, {"opencode"}} {
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
	// Sorted, and each named once however many enrolments named it.
	if want := []string{"claude", "opencode", "pi"}; !slices.Equal(got[0].Agents, want) {
		t.Errorf("agents = %v, want %v: every agent this tree still carries",
			got[0].Agents, want)
	}
}

// What it is bounded by, and why the entry is not simply cumulative: an
// enrolled agent whose rules are missing from the home is a doctor failure and
// a non-zero exit, so a name that could never leave would fail the command for
// ever on an agent the operator had removed.
func TestRecordingAnEnrolmentDropsAnAgentTheTreeNoLongerCarries(t *testing.T) {
	dir := t.TempDir()
	tree := enrolledTree(t, dir, "claude", "pi")

	if err := recordEnrolment(dir, EnrolledTree{
		Dir: tree, Operator: "op", Agents: []string{"claude", "pi"},
	}); err != nil {
		t.Fatal(err)
	}
	// The operator takes pi out of the tree and re-enrols for claude alone.
	for _, marker := range agentTargets["pi"].detect {
		if err := os.RemoveAll(filepath.Join(tree, marker)); err != nil {
			t.Fatal(err)
		}
	}
	if err := recordEnrolment(dir, EnrolledTree{
		Dir: tree, Operator: "op", Agents: []string{"claude"},
	}); err != nil {
		t.Fatal(err)
	}

	got := readEnrolled(dir)
	if len(got) != 1 || !slices.Equal(got[0].Agents, []string{"claude"}) {
		t.Errorf("agents = %+v, want [claude]: an agent whose configuration is gone "+
			"from the tree would otherwise fail doctor for ever", got)
	}
}

// The operator is the later enrolment's, not accumulated: a tree has one owner,
// and re-enrolling under another account is that account taking it over.
func TestRecordingAnEnrolmentTakesTheLaterOperator(t *testing.T) {
	dir := t.TempDir()
	tree := filepath.Join(dir, "project")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, operator := range []string{"first", "second"} {
		if err := recordEnrolment(dir, EnrolledTree{
			Dir: tree, Operator: operator, Agents: []string{"claude"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := readEnrolled(dir)
	if len(got) != 1 || got[0].Operator != "second" {
		t.Errorf("operator = %+v, want the later enrolment's", got)
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
		{Dir: here, Operator: "op", Agents: []string{"opencode"}},
		{Dir: filepath.Join(dir, "gone"), Operator: "op", Agents: []string{"claude"}},
	} {
		if err := recordEnrolment(dir, tree); err != nil {
			t.Fatal(err)
		}
	}
	agents, stale := enrolledAgents(dir)
	if !slices.Equal(agents, []string{"opencode"}) {
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
	reportAgentRules(&report, t.TempDir(), []string{"opencode"})

	var found bool
	for _, finding := range report.Findings {
		if finding.Status == StatusFailed && strings.Contains(finding.Detail, "opencode") {
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
