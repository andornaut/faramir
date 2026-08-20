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

// Every agent gets a row, whether or not it looks in use. Which agents an
// operator runs is not a thing this can know, so a row per agent is the report
// and the states are what differ.
func TestAgentRulesReportsEveryKnownAgent(t *testing.T) {
	var report DoctorReport
	reportAgentRules(&report, t.TempDir(), nil)

	if len(report.Findings) != len(knownAgents()) {
		t.Fatalf("%d rows for %d agents: %+v",
			len(report.Findings), len(knownAgents()), report.Findings)
	}
	for _, name := range knownAgents() {
		finding(t, report, name)
	}
}

// An empty home: nobody runs any of them from this account, which is not a
// state a host is worse for.
func TestAgentRulesAreNotAFaultWhereNobodyRunsTheAgent(t *testing.T) {
	var report DoctorReport
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
	target := agentTargets["claude"]
	for _, file := range target.accountFiles {
		touch(t, home, file.path)
	}

	var report DoctorReport
	reportAgentRules(&report, home, nil)

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
// are refused nothing. Half an arrangement, and the half that is gone is the
// half that was doing the work.
func TestAgentRulesFailWhenTheAgentIsHereAndItsRulesAreNot(t *testing.T) {
	home := t.TempDir()
	// Its own directory and none of the rules: the shape an operator who
	// installed the agent after running `faramir init` is left in.
	touch(t, home, ".claude/some-state.json")

	var report DoctorReport
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
	for _, file := range agentTargets["opencode"].accountFiles {
		touch(t, home, file.path)
	}

	var report DoctorReport
	reportAgentRules(&report, home, nil)

	if got := finding(t, report, "opencode"); got.Status != StatusOK {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusOK, got.Detail)
	}
	if report.Failed {
		t.Error("rules written ahead of the agent failed the report")
	}
}

// An agent that carries its rules in the extension an enrolment installs has
// nothing in this home to find, and nothing missing from it either. Reported
// rather than left out, a check that vanishes being indistinguishable from one
// nobody wrote -- and not a fault, whether or not the agent is here.
func TestAgentRulesSayWhereAnExtensionCarriesThem(t *testing.T) {
	// Fatal rather than skipped: pi gaining account-wide rules makes this case
	// wrong rather than inapplicable, and a skip would drop it in silence.
	if len(agentTargets["pi"].accountFiles) != 0 {
		t.Fatal("pi now writes account-wide rules, so it is no longer the agent " +
			"whose rules live in an extension; rewrite this against whichever is")
	}
	for _, name := range []string{"installed here", "not installed here"} {
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			if name == "installed here" {
				touch(t, home, ".pi/state.json")
			}
			var report DoctorReport
			reportAgentRules(&report, home, nil)

			got := finding(t, report, "pi")
			if got.Status != StatusNA {
				t.Errorf("status = %q, want %q: %s", got.Status, StatusNA, got.Detail)
			}
			if !strings.Contains(got.Detail, "extension") {
				t.Errorf("detail does not say where its rules are: %s", got.Detail)
			}
			if report.Failed {
				t.Error("an agent whose rules live elsewhere failed the report")
			}
		})
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
	if len(report.Findings) != 1 || !strings.Contains(report.Findings[0].Detail, "--agent-user") {
		t.Errorf("finding does not say how to ask it: %+v", report.Findings)
	}
}
