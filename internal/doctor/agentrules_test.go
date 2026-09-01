package doctor

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

// touch creates a file and the directories above it, for a home a test is
// building up one marker at a time.
func touch(t *testing.T, home, rel string) {
	t.Helper()
	path := filepath.Join(home, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// finding is the one row named, or a failure: every case here is about a single
// agent's state, and asserting on the whole list would couple each case to how
// many agents exist.
func finding(t *testing.T, report Report, agent string) Finding {
	t.Helper()
	for _, f := range report.Findings {
		if f.Name == "agent rules" && strings.HasPrefix(f.Detail, agent+":") {
			return f
		}
		// The failed row leads with the agent and a verb rather than a colon.
		if f.Name == "agent rules" && strings.HasPrefix(f.Detail, agent+" is in this home") {
			return f
		}
	}
	t.Fatalf("no row for %s in %+v", agent, report.Findings)
	return Finding{}
}

// Every agent gets a row, whether or not it looks in use. Which agents an
// operator runs is not a thing this can know, so a row per agent is the report
// and the states are what differ.
func TestAgentRulesReportsEveryKnownAgent(t *testing.T) {
	var report Report
	reportAgentRules(&report, t.TempDir(), nil)

	if len(report.Findings) != len(agentcfg.Known()) {
		t.Fatalf("%d rows for %d agents: %+v",
			len(report.Findings), len(agentcfg.Known()), report.Findings)
	}
	for _, name := range agentcfg.Known() {
		finding(t, report, name)
	}
}

// An empty home: nobody runs any of them from this account, which is not a
// state a host is worse for.
func TestAgentRulesAreNotAFaultWhereNobodyRunsTheAgent(t *testing.T) {
	var report Report
	reportAgentRules(&report, t.TempDir(), nil)

	if report.Failed {
		t.Error("an account that runs no agent failed the report")
	}
	got := finding(t, report, "claude")
	if got.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusNA, got.Detail)
	}
	if !strings.Contains(got.Detail, "nothing here") {
		t.Errorf("detail does not say the agent is absent: %s", got.Detail)
	}
}

// The rules are there, so the row names them: an operator checking this wants
// the paths, the whole finding being about files that are meant to exist.
func TestAgentRulesNamesTheFilesWhenTheyAreThere(t *testing.T) {
	home := t.TempDir()
	target := agentcfg.Targets["claude"]
	for _, file := range target.AccountFiles {
		touch(t, home, file.Path)
	}

	var report Report
	reportAgentRules(&report, home, nil)

	got := finding(t, report, "claude")
	if got.Status != StatusOK {
		t.Fatalf("status = %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	for _, file := range target.AccountFiles {
		if !strings.Contains(got.Detail, "~/"+file.Path) {
			t.Errorf("detail does not name ~/%s: %s", file.Path, got.Detail)
		}
	}
}

// The one state that is a fault: the agent is in this home and the rules that
// refuse its file tools are not, so what this install protects is refused
// nothing. Half an arrangement, and the half that is gone is the half that was
// doing the work.
func TestAgentRulesFailWhenTheAgentIsHereAndItsRulesAreNot(t *testing.T) {
	home := t.TempDir()
	// Its own directory and none of the rules: the shape an operator who
	// installed the agent after running `faramir init` is left in.
	touch(t, home, ".claude/some-state.json")

	var report Report
	reportAgentRules(&report, home, nil)

	got := finding(t, report, "claude")
	if got.Status != StatusFailed {
		t.Fatalf("status = %q, want %q: %s", got.Status, StatusFailed, got.Detail)
	}
	if !report.Failed {
		t.Error("a missing rule file did not fail the report")
	}
	// The remedy is the point of the finding: without it this names a state and
	// no way out of it.
	if !strings.Contains(got.Detail, "faramir init --agent claude") {
		t.Errorf("detail does not say how to fix it: %s", got.Detail)
	}
}

// Rules present but the agent's own directory absent is still OK rather than a
// fault: `faramir init` writes every agent's rules now, so a rule file for an
// agent nobody has installed is the ordinary state and not a finding.
func TestAgentRulesAreOKWhereOnlyTheRulesAreThere(t *testing.T) {
	home := t.TempDir()
	for _, file := range agentcfg.Targets["opencode"].AccountFiles {
		touch(t, home, file.Path)
	}

	var report Report
	reportAgentRules(&report, home, nil)

	if got := finding(t, report, "opencode"); got.Status != StatusOK {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	if report.Failed {
		t.Error("rules written ahead of the agent failed the report")
	}
}

// The lookup half: without an operator to ask about, this is a question that
// was not put rather than a host that passed it.
func TestAgentRulesAreUnaskedWithoutAnOperator(t *testing.T) {
	var report Report
	diagnoseAgentRules(&report, Options{})

	if report.NotAsked != 1 {
		t.Errorf("not_asked = %d, want 1: %+v", report.NotAsked, report.Findings)
	}
	if report.Failed {
		t.Error("a question that could not be put failed the report")
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "--agent-user") {
		t.Errorf("finding does not say how to ask it: %+v", report.Findings)
	}
}

// The rules an install writes name the paths this install writes, plus what a
// [[secret.link]] or [[secret.block]] entry declares: see protectedpaths.go,
// which refuses to compile in a rule for a file faramir did not choose because
// it "makes the default look more protective than it is". A finding that names
// one anyway makes the same claim in prose, and an operator reading it believes
// running the command it advises protects a key it will not touch.
func TestTheMissingRulesFindingClaimsOnlyWhatTheRulesCover(t *testing.T) {
	home := t.TempDir()
	touch(t, home, ".claude/some-state.json")

	var report Report
	reportAgentRules(&report, home, nil)

	got := finding(t, report, "claude")
	for _, path := range []string{"~/.ssh", ".config/sops"} {
		if strings.Contains(got.Detail, path) {
			t.Errorf("the finding names %s, which the default install does not "+
				"cover: %s", path, got.Detail)
		}
	}
	// It still has to say what is at stake, or it names a missing file and no
	// reason to care.
	for _, want := range []string{"this install protects", "no uid boundary"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("the finding does not say %q: %s", want, got.Detail)
		}
	}
}

// `doctor` reports Antigravity as an agent with account-wide files rather than
// one with none. It has no rule file and never will, its permission lists being
// its own state, but the hook it reads for every workspace is written into a
// home like any other account file, and the report an operator reads to check
// coverage has to name it.
func TestDoctorReportsAntigravitysAccountWideHook(t *testing.T) {
	if len(agentcfg.Targets["antigravity"].AccountFiles) == 0 {
		t.Fatal("the IDE has no account-wide files, so nothing refuses its file " +
			"tools outside an enrolled tree")
	}
	// A home the agent is in: an empty one is reported as an agent nobody runs
	// here, which is a different finding and true of every target.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config/Antigravity"), 0o700); err != nil {
		t.Fatal(err)
	}
	var report Report
	reportAgentRules(&report, home, nil)

	got := finding(t, report, "antigravity")
	// Absent from a home nothing was installed into, which is a missing file
	// rather than an agent that can have none.
	if got.Status == StatusNA {
		t.Errorf("doctor still reports it as an agent that can have no rules: %s",
			got.Detail)
	}
	if !strings.Contains(got.Detail, "hooks.json") {
		t.Errorf("doctor does not name the file its refusals are written into: %s",
			got.Detail)
	}
	if strings.Contains(got.Detail, "extension") {
		t.Errorf("doctor says an extension carries Antigravity's rules: %s", got.Detail)
	}
}

// A tree enrolled for an agent that leaves no trace in the home is the case a
// home alone cannot see, and the one this record exists for.
func TestAnEnrolledAgentIsAFaultEvenWithNothingInTheHome(t *testing.T) {
	var report Report
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
