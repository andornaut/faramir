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

// A tree carrying no agent is still an enrolment. The share happened and the
// instructions file was written, and doctor checks that file off this record:
// an entry dropped here is a tree faramir has written to and reports nothing
// about.
func TestRecordingAnEnrolmentKeepsATreeWithNoAgent(t *testing.T) {
	dir := t.TempDir()
	tree := enrolledTree(t, dir)

	if err := recordEnrolment(dir, EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}
	got := readEnrolled(dir)
	if len(got) != 1 {
		t.Fatalf("recorded %d entries, want 1: %+v", len(got), got)
	}
	if got[0].Dir != tree {
		t.Errorf("recorded %q, want %q", got[0].Dir, tree)
	}
	// The positive control: a record naming no directory is still nothing to
	// write, so this does not pass by having dropped the guard entirely.
	if err := recordEnrolment(dir, EnrolledTree{AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}
	if got := readEnrolled(dir); len(got) != 1 {
		t.Errorf("a record naming no tree was written: %+v", got)
	}
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
			Dir: tree, AgentUser: "op", Agents: agents,
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
		Dir: tree, AgentUser: "op", Agents: []string{"claude", "pi"},
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
		Dir: tree, AgentUser: "op", Agents: []string{"claude"},
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
			Dir: tree, AgentUser: operator, Agents: []string{"claude"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := readEnrolled(dir)
	if len(got) != 1 || got[0].AgentUser != "second" {
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
		{Dir: here, AgentUser: "op", Agents: []string{"opencode"}},
		{Dir: filepath.Join(dir, "gone"), AgentUser: "op", Agents: []string{"claude"}},
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

// A record that could not be read is not a record naming nothing. Reported as
// the second, an operator with an enrolled fleet is told they have none, and
// the step that says so is an "ok".
func TestAnUnreadableRecordIsToldApartFromAnEmptyOne(t *testing.T) {
	dir := t.TempDir()
	// No file at all: the ordinary state of a host that has enrolled nothing.
	if trees, why := readEnrolledWhy(dir); trees != nil || why != "" {
		t.Errorf("a host with no record reported %v / %q, want nothing and no reason", trees, why)
	}
	path := filepath.Join(dir, enrolledFile)
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	trees, why := readEnrolledWhy(dir)
	if trees != nil {
		t.Errorf("an unreadable record produced trees: %v", trees)
	}
	if why == "" || !strings.Contains(why, path) {
		t.Errorf("the reason does not name the file: %q", why)
	}
	// And a record that reads is still read.
	body := `[{"dir":"/home/op/project","agent_user":"op","agents":["claude"]}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if trees, why := readEnrolledWhy(dir); len(trees) != 1 || why != "" {
		t.Errorf("a good record read as %v / %q", trees, why)
	}
}

// The record is advisory and is written by more than one release, so a
// directory it names is not proof that enrolling it would be allowed today. An
// entry for one of faramir's own directories had every `init` writing an
// agent's settings back into it, after an operator had cleaned them out and
// after `init-project` had started refusing to make such an entry at all.
func TestARecordedTreeIsHeldToWhatAnEnrolmentWouldAllow(t *testing.T) {
	for _, dir := range []string{
		"/var/lib/" + DefaultBrokerUser,
		"/var/lib/" + DefaultKeeperUser,
		"/var/lib/" + DefaultExecUser,
		"/etc/faramir",
		"/etc/faramir/secrets",
		"/var/log/faramir",
	} {
		if err := refuseInstallDirs(dir, "/etc/faramir"); err == nil {
			t.Errorf("a recorded %s would be written into: init-project refuses to "+
				"enrol it, and the step that reads the record asks the same question", dir)
		}
	}
	// The ordinary case the check must not reach.
	if err := refuseInstallDirs("/home/op/project", "/etc/faramir"); err != nil {
		t.Errorf("a recorded project tree was refused: %v", err)
	}
}

// Two enrolments each read the record, add their own tree and write the whole
// file back, so one entry is lost. The tree is enrolled either way -- the share
// and the agent files are already written by the time this runs -- so an entry
// that never lands leaves a tree `faramir init` stops maintaining and `doctor`
// stops checking, looking like every other enrolled tree from the outside.
func TestRecordingIsRefusedWhenTheRecordMovedUnderIt(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, enrolledFile)

	// The first enrolment writes the record, there being none.
	if err := recordEnrolment(dir, EnrolledTree{Dir: "/home/op/one", AgentUser: "op"}); err != nil {
		t.Fatalf("the first enrolment could not record itself: %v", err)
	}
	if trees := readEnrolled(dir); len(trees) != 1 {
		t.Fatalf("the record holds %d tree(s), want 1", len(trees))
	}

	// A second enrolment reading this record and writing it back is ordinary.
	if err := recordEnrolment(dir, EnrolledTree{Dir: "/home/op/two", AgentUser: "op"}); err != nil {
		t.Fatalf("a second enrolment was refused: %v", err)
	}
	if trees := readEnrolled(dir); len(trees) != 2 {
		t.Fatalf("the record holds %d tree(s), want 2", len(trees))
	}

	// What a collision looks like: something wrote the record between this
	// enrolment's read and its write. Simulated by moving the file after the
	// digest is taken, which is what a parallel enrolment does.
	before, err := recordDigest(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("[]\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	body := []byte(`[{"dir":"/home/op/three","agent_user":"op","agents":null}]` + "\n")
	_, err = (fsys{}).writeFileExpecting(path, body, 0o600, keep, keep, before)
	if err == nil {
		t.Fatal("a record write onto a record something else had written was accepted")
	}
	if !strings.Contains(err.Error(), "changed while this was working on it") {
		t.Errorf("the refusal does not say what happened: %v", err)
	}
	// And it wrote nothing, so the record is what the other writer left.
	if got, _ := os.ReadFile(path); string(got) != "[]\n" {
		t.Errorf("the record is %q, so the refused write landed anyway", got)
	}
}
