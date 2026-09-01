package agentcfg

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostfs"
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
		for _, marker := range Targets[name].Detect {
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

	if err := RecordEnrolment(dir, EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}
	got := ReadEnrolled(dir)
	if len(got) != 1 {
		t.Fatalf("recorded %d entries, want 1: %+v", len(got), got)
	}
	if got[0].Dir != tree {
		t.Errorf("recorded %q, want %q", got[0].Dir, tree)
	}
	// The positive control: a record naming no directory is still nothing to
	// write, so this does not pass by having dropped the guard entirely.
	if err := RecordEnrolment(dir, EnrolledTree{AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}
	if got := ReadEnrolled(dir); len(got) != 1 {
		t.Errorf("a record naming no tree was written: %+v", got)
	}
}

// An enrolment is the one thing that knows a tree was enrolled and for what.
// One entry per directory, and enrolling one agent by name does not drop the
// others: what they read is still in the tree, and an entry
// dropped here is a tree doctor stops checking those agents' account-wide rules
// for, which nothing would report.
func TestRecordingAnEnrolmentKeepsTheAgentsATreeStillCarries(t *testing.T) {
	dir := t.TempDir()
	tree := enrolledTree(t, dir, "claude", "opencode", "pi")

	for _, agents := range [][]string{{"claude"}, {"opencode", "pi"}, {"opencode"}} {
		if err := RecordEnrolment(dir, EnrolledTree{
			Dir: tree, AgentUser: "op", Agents: agents,
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := ReadEnrolled(dir)
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

	if err := RecordEnrolment(dir, EnrolledTree{
		Dir: tree, AgentUser: "op", Agents: []string{"claude", "pi"},
	}); err != nil {
		t.Fatal(err)
	}
	// The operator takes pi out of the tree and re-enrols for claude alone.
	for _, marker := range Targets["pi"].Detect {
		if err := os.RemoveAll(filepath.Join(tree, marker)); err != nil {
			t.Fatal(err)
		}
	}
	if err := RecordEnrolment(dir, EnrolledTree{
		Dir: tree, AgentUser: "op", Agents: []string{"claude"},
	}); err != nil {
		t.Fatal(err)
	}

	got := ReadEnrolled(dir)
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
		if err := RecordEnrolment(dir, EnrolledTree{
			Dir: tree, AgentUser: operator, Agents: []string{"claude"},
		}); err != nil {
			t.Fatal(err)
		}
	}
	got := ReadEnrolled(dir)
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
		if err := RecordEnrolment(dir, tree); err != nil {
			t.Fatal(err)
		}
	}
	agents, stale := EnrolledAgents(dir)
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
	if err := os.WriteFile(EnrolledPath(dir), []byte("{not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if got := ReadEnrolled(dir); got != nil {
		t.Errorf("read %+v from a file that does not parse, want nothing", got)
	}
	agents, stale := EnrolledAgents(dir)
	if agents != nil || stale != nil {
		t.Errorf("got %v and %+v, want nothing from an unreadable record", agents, stale)
	}
}

// A record that could not be read is not a record naming nothing. Reported as
// the second, an operator with an enrolled fleet is told they have none, and
// the step that says so is an "ok".
func TestAnUnreadableRecordIsToldApartFromAnEmptyOne(t *testing.T) {
	dir := t.TempDir()
	// No file at all: the ordinary state of a host that has enrolled nothing.
	if trees, err := ReadEnrolledWhy(dir); trees != nil || err != nil {
		t.Errorf("a host with no record reported %v / %v, want nothing and no reason", trees, err)
	}
	path := filepath.Join(dir, enrolledFile)
	if err := os.WriteFile(path, []byte("{ not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	trees, err := ReadEnrolledWhy(dir)
	if trees != nil {
		t.Errorf("an unreadable record produced trees: %v", trees)
	}
	if err == nil || !strings.Contains(err.Error(), path) {
		t.Errorf("the reason does not name the file: %v", err)
	}
	// Damaged rather than unreadable: the caller tells the two apart, so this
	// one must not arrive looking like a permission denial.
	if errors.Is(err, os.ErrPermission) {
		t.Errorf("a damaged record reads as a permission denial: %v", err)
	}
	// And a record that reads is still read.
	body := `[{"dir":"/home/op/project","agent_user":"op","agents":["claude"]}]`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	if trees, err := ReadEnrolledWhy(dir); len(trees) != 1 || err != nil {
		t.Errorf("a good record read as %v / %v", trees, err)
	}
}

// A record the caller may not read is not a damaged one. The file is 0600 root
// and `doctor` is runnable unprivileged, so this is the ordinary case for an
// agent and has to be told apart from a record that will not parse.
func TestAnUnreadableRecordIsToldApartFromAForbiddenOne(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read the file whatever its mode")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, enrolledFile)
	if err := os.WriteFile(path, []byte("[]"), 0o000); err != nil {
		t.Fatal(err)
	}
	_, err := ReadEnrolledWhy(dir)
	if !errors.Is(err, os.ErrPermission) {
		t.Errorf("a record the caller may not read gave %v, want a permission error", err)
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
	if err := RecordEnrolment(dir, EnrolledTree{Dir: "/home/op/one", AgentUser: "op"}); err != nil {
		t.Fatalf("the first enrolment could not record itself: %v", err)
	}
	if trees := ReadEnrolled(dir); len(trees) != 1 {
		t.Fatalf("the record holds %d tree(s), want 1", len(trees))
	}

	// A second enrolment reading this record and writing it back is ordinary.
	if err := RecordEnrolment(dir, EnrolledTree{Dir: "/home/op/two", AgentUser: "op"}); err != nil {
		t.Fatalf("a second enrolment was refused: %v", err)
	}
	if trees := ReadEnrolled(dir); len(trees) != 2 {
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
	_, err = (hostfs.FS{}).WriteFileExpecting(path, body, 0o600, before)
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
