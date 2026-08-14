package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// enrolTree writes what `init-project` writes for one agent into a tree, and
// records the enrolment, so the check below is comparing against a tree an
// enrolment actually produced rather than one a test hand-built.
func enrolTree(t *testing.T, configDir, name string) string {
	t.Helper()
	tree := t.TempDir()
	target := agentTargets[name]
	render := func(file agentFile) ([]byte, error) {
		return assetFor(target, file, configDir)
	}
	if _, _, err := writeAgentFiles(
		fsys{}, tree, keep, keep, 0o2770|os.ModeSetgid, true, render, target.files); err != nil {
		t.Fatal(err)
	}
	if err := recordEnrolment(configDir, EnrolledTree{
		Dir: tree, Operator: "op", Agents: []string{name},
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
