package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
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
func finding(t *testing.T, report DoctorReport, agent string) Finding {
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

// Every agent gets a row, whether or not it looks in use.  Which agents an
// operator runs is not a thing this can know, so a row per agent is the report
// and the states are what differ.
func TestAgentRulesReportsEveryKnownAgent(t *testing.T) {
	var report DoctorReport
	reportAgentRules(&report, t.TempDir())

	if len(report.Findings) != len(agentNames()) {
		t.Fatalf("%d rows for %d agents: %+v",
			len(report.Findings), len(agentNames()), report.Findings)
	}
	for _, name := range agentNames() {
		finding(t, report, name)
	}
}

// An empty home: nobody runs any of them from this account, which is not a
// state a host is worse for.
func TestAgentRulesAreNotAFaultWhereNobodyRunsTheAgent(t *testing.T) {
	var report DoctorReport
	reportAgentRules(&report, t.TempDir())

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
	target := agentTargets["claude"]
	for _, file := range target.accountFiles {
		touch(t, home, file.path)
	}

	var report DoctorReport
	reportAgentRules(&report, home)

	got := finding(t, report, "claude")
	if got.Status != StatusOK {
		t.Fatalf("status = %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	for _, file := range target.accountFiles {
		if !strings.Contains(got.Detail, "~/"+file.path) {
			t.Errorf("detail does not name ~/%s: %s", file.path, got.Detail)
		}
	}
}

// The one state that is a fault: the agent is in this home and the rules that
// refuse its file tools are not, so the keys under ~/.ssh and ~/.config/sops
// are refused nothing.  Half an arrangement, and the half that is gone is the
// half that was doing the work.
func TestAgentRulesFailWhenTheAgentIsHereAndItsRulesAreNot(t *testing.T) {
	home := t.TempDir()
	// Its own directory and none of the rules: the shape an operator who
	// installed the agent after running `faramir init` is left in.
	touch(t, home, ".claude/some-state.json")

	var report DoctorReport
	reportAgentRules(&report, home)

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
	for _, file := range agentTargets["gemini"].accountFiles {
		touch(t, home, file.path)
	}

	var report DoctorReport
	reportAgentRules(&report, home)

	if got := finding(t, report, "gemini"); got.Status != StatusOK {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	if report.Failed {
		t.Error("rules written ahead of the agent failed the report")
	}
}

// An agent faramir writes no rules for, and that is installed here, has a gap
// today: its extension refuses the shell tools, and nothing refuses its file
// tools.  Warn rather than n/a, which would read as nothing to see, and rather
// than failed, which there is no command to clear.
func TestAgentRulesWarnWhereNothingRefusesTheFileTools(t *testing.T) {
	if len(agentTargets["pi"].accountFiles) != 0 {
		t.Skip("pi now writes account-wide rules; this case has moved")
	}
	home := t.TempDir()
	touch(t, home, ".pi/state.json")

	var report DoctorReport
	reportAgentRules(&report, home)

	got := finding(t, report, "pi")
	if got.Status != StatusWarn {
		t.Fatalf("status = %q, want %q: %s", got.Status, StatusWarn, got.Detail)
	}
	// Which tools are covered and which are not is the whole finding: "no rules"
	// alone reads as an agent nobody configured.
	for _, want := range []string{"file tools", ".ssh"} {
		if !strings.Contains(got.Detail, want) {
			t.Errorf("detail does not say %q: %s", want, got.Detail)
		}
	}
	// Warn, not failed: there is no `faramir init --agent pi` that writes these,
	// so failing the report would leave an operator no way to clear it.
	if report.Failed {
		t.Error("a gap with no remedy failed the whole report")
	}
}

// The same agent, not installed here: no gap on a host nobody runs it from.
func TestAgentRulesAreNotAFaultWhereThatAgentIsAbsent(t *testing.T) {
	if len(agentTargets["pi"].accountFiles) != 0 {
		t.Skip("pi now writes account-wide rules; this case has moved")
	}
	var report DoctorReport
	reportAgentRules(&report, t.TempDir())

	if got := finding(t, report, "pi"); got.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusNA, got.Detail)
	}
}

// The lookup half: without an operator to ask about, this is a question that
// was not put rather than a host that passed it.
func TestAgentRulesAreUnaskedWithoutAnOperator(t *testing.T) {
	var report DoctorReport
	diagnoseAgentRules(&report, DoctorOptions{})

	if report.NotAsked != 1 {
		t.Errorf("not_asked = %d, want 1: %+v", report.NotAsked, report.Findings)
	}
	if report.Failed {
		t.Error("a question that could not be put failed the report")
	}
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "--operator-user") {
		t.Errorf("finding does not say how to ask it: %+v", report.Findings)
	}
}
