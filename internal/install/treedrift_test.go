package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// enrolTree writes what `init-project` writes for these agents into a tree, and
// records the enrolment, so the check below is comparing against a tree an
// enrolment actually produced rather than one a test hand-built.
func enrolTree(t *testing.T, configDir string, names ...string) string {
	t.Helper()
	tree := t.TempDir()
	for _, name := range names {
		target := agentTargets[name]
		render := func(file agentFile) ([]byte, error) {
			return assetFor(target, file, configDir)
		}
		if _, _, err := writeAgentFiles(
			fsys{}, tree, keep, keep, 0o2770|os.ModeSetgid, true, render, target.files); err != nil {
			t.Fatal(err)
		}
	}
	if err := recordEnrolment(configDir, EnrolledTree{
		Dir: tree, AgentUser: "op", Agents: names,
	}); err != nil {
		t.Fatal(err)
	}
	return tree
}

// findings returns the details of every finding with this name.
func findings(report DoctorReport, name string) []Finding {
	var out []Finding
	for _, finding := range report.Findings {
		if finding.Name == name {
			out = append(out, finding)
		}
	}
	return out
}

// A tree still carrying what the enrolment wrote is the ordinary answer.
func TestTreeConfigIsOKWhereTheEnrolmentSurvives(t *testing.T) {
	configDir := t.TempDir()
	enrolTree(t, configDir, "claude")

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})

	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK", got)
	}
	if report.Failed {
		t.Error("an intact tree failed the report")
	}
}

// The case this exists for: a tree is shared with the client group and unlink is
// a permission on the directory, so a brokered command can replace the file
// naming the hook.  A hand edit reaches the same place.  Nothing else would say
// that the project stopped being redacted.
func TestTreeConfigReportsAFileThatNoLongerCarriesTheHook(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.json")
	// What replacing it looks like: valid configuration of somebody's own, with
	// nothing of faramir's in it.
	if err := os.WriteFile(settings, []byte(`{"model":"whatever"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})

	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", got)
	}
	if !strings.Contains(got[0].Detail, settings) {
		t.Errorf("the finding does not name the file: %s", got[0].Detail)
	}
	// Warned, not failed: a tree enrolled with --hook=false reads the same way
	// and the record cannot tell the two apart.
	if report.Failed {
		t.Error("tree config drift failed the report rather than warning")
	}
}

// The file is the project's to edit, and only faramir's keys are its own. A
// project that added keys beside them still carries what the enrolment wrote.
func TestTreeConfigAcceptsTheProjectsOwnKeysBesideOurs(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.json")

	current, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := mergeJSON(current, []byte(`{"model":"opus","env":{"X":"1"}}`+"\n"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, theirs, 0o640); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})

	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK: a project's own keys are not drift", got)
	}
}

// A tree that has gone is diagnoseAgentRules' finding, and reporting it twice
// would have an operator chasing a file on a path that is not there.
func TestTreeConfigPassesOverATreeThatIsGone(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	if err := os.RemoveAll(tree); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})

	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK", got)
	}
	if strings.Contains(got[0].Detail, tree) {
		t.Errorf("a tree that is gone was named here as well: %s", got[0].Detail)
	}
}

// A file an install would refuse to write is named before a run stops on it.
func TestEditableFilesReportsWhatAnInstallWouldRefuse(t *testing.T) {
	home := t.TempDir()
	// A dangling link at a path init edits, which editedFile refuses.
	path := filepath.Join(home, agentTargets["claude"].homeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nothing-here.md"), path); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	reportEditableFiles(&report, home, os.Getuid(), DoctorOptions{ConfigDir: t.TempDir()})

	got := findings(report, "agent file ownership")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", got)
	}
	if !strings.Contains(got[0].Detail, path) {
		t.Errorf("the finding does not name the file: %s", got[0].Detail)
	}
	// Warned, not failed: nothing is unguarded, and what is named is a file the
	// next run cannot update.
	if report.Failed {
		t.Error("a file an install would refuse failed the report")
	}
}

// The tree's own instructions file is asked about too.  Every enrolment writes
// it whatever the tree was enrolled for, and no target names it, so a tree
// whose AGENTS.md is a link out of it would pass this check clean and then stop
// the next `init-project`.
func TestEditableFilesReportsATreesOwnInstructionsFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	path := filepath.Join(tree, "AGENTS.md")
	if err := os.Symlink(filepath.Join(tree, "nothing-here.md"), path); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	reportEditableFiles(&report, t.TempDir(), os.Getuid(), DoctorOptions{ConfigDir: configDir})

	got := findings(report, "agent file ownership")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", got)
	}
	if !strings.Contains(got[0].Detail, path) {
		t.Errorf("the finding does not name the tree's instructions file: %s", got[0].Detail)
	}
}

// Two of a tree's files that are one file are found here as well, which takes
// asking about every path an enrolment writes there together: agent by agent,
// each call sees one half of the pair and reports nothing.
func TestEditableFilesReportsTwoTreeFilesThatAreOneFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "antigravity", "claude")
	// Antigravity's MCP registration pointed at Claude Code's, the two reading
	// the same shape out of a file each.
	linked := filepath.Join(tree, ".agents", "mcp_config.json")
	if err := os.Remove(linked); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(tree, ".mcp.json"), linked); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	reportEditableFiles(&report, t.TempDir(), os.Getuid(), DoctorOptions{ConfigDir: configDir})

	got := findings(report, "agent file ownership")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", got)
	}
	if !strings.Contains(got[0].Detail, "are one file") {
		t.Errorf("the finding does not report the pair: %s", got[0].Detail)
	}
}

// A home whose files are all the operator's, or not there yet, is the ordinary
// answer and must not read as a warning.
func TestEditableFilesIsOKWhereEveryFileIsTheOperatorsOwn(t *testing.T) {
	var report DoctorReport
	reportEditableFiles(&report, t.TempDir(), os.Getuid(), DoctorOptions{ConfigDir: t.TempDir()})

	got := findings(report, "agent file ownership")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK", got)
	}
}

// An account with nothing of faramir's in its home has nothing to report.
func TestEditableFilesIsOKWhereThereIsNothingToRefuse(t *testing.T) {
	var report DoctorReport
	diagnoseEditableFiles(&report, DoctorOptions{ConfigDir: t.TempDir()})

	got := findings(report, "agent file ownership")
	if len(got) != 1 {
		t.Fatalf("findings = %+v, want one", got)
	}
	// With no operator named it cannot be asked at all, which is counted as
	// unasked rather than passed: a check that could not run is not a check
	// that found nothing.
	if report.NotAsked != 1 {
		t.Errorf("NotAsked = %d, want 1: a check that could not run must not read "+
			"as one that passed", report.NotAsked)
	}
	if !strings.Contains(got[0].Detail, "--agent-user") {
		t.Errorf("the finding does not say how to ask it: %s", got[0].Detail)
	}
}
