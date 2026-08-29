package install

import (
	"encoding/json"
	"os"
	"os/user"
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
			fsys{}, nil, tree, "", keep, keep, 0o2770|os.ModeSetgid, true, render, target.files); err != nil {
			t.Fatal(err)
		}
	}
	// The instruction files every enrolment writes, carrying the credentials
	// section and, for a rules file, the frontmatter that loads it: the tree
	// check compares them now, so a fixture without them reads as drifted.
	section := sectionBegin + "\ntest section\n" + sectionEnd + "\n"
	if err := os.WriteFile(treeInstructionsFile(tree), []byte(section), 0o640); err != nil {
		t.Fatal(err)
	}
	for _, name := range names {
		rules := agentTargets[name].treeInstructions
		if rules.path == "" {
			continue
		}
		path := filepath.Join(tree, rules.path)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(rules.head+section), 0o640); err != nil {
			t.Fatal(err)
		}
	}
	// The account the tree is recorded for is this one: an unresolvable name is
	// its own case, reported as unasked rather than judged as somebody else.
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if err := recordEnrolment(configDir, EnrolledTree{
		Dir: tree, AgentUser: me.Username, Agents: names,
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
// naming the hook. A hand edit reaches the same place. Nothing else would say
// that the project stopped being redacted.
func TestTreeConfigReportsAFileThatNoLongerCarriesTheHook(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.local.json")
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
	// Warned, not failed: the record says what was enrolled, not what the tree
	// is now, and a checkout that moved or a branch without these files reads
	// the same way from here.
	if report.Failed {
		t.Error("tree config drift failed the report rather than warning")
	}
}

// The file is the project's to edit, and only faramir's keys are its own. A
// project that added keys beside them still carries what the enrolment wrote.
func TestTreeConfigAcceptsTheProjectsOwnKeysBesideOurs(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.local.json")

	current, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := mergeJSON(current, []byte(`{"model":"opus","env":{"X":"1"}}`+"\n"), nil)
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
	// Fatal, since the assertion below indexes it: a check that produced no
	// finding would otherwise panic here rather than report.
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Fatalf("findings = %+v, want one OK", got)
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

// The tree's own instructions file is asked about too. Every enrolment writes
// it whatever the tree was enrolled for, and no target names it, so a tree
// whose AGENTS.md is a link out of it would pass this check clean and then stop
// the next `init-project`.
func TestEditableFilesReportsATreesOwnInstructionsFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	path := filepath.Join(tree, "AGENTS.md")
	// Only the dangling link: with the fixture's CLAUDE.md standing beside it,
	// the tree's own file would resolve there instead and the link go unasked.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tree, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
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

// A tree whose CLAUDE.md is a link to its AGENTS.md is what an operator keeping
// one file for every agent has, and the enrolment writes it once. Reported as a
// pair of writes with one survivor, doctor would name a file the next
// `init-project` writes without complaint.
func TestEditableFilesAcceptsATreesLinkedClaudeFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	agents := filepath.Join(tree, "AGENTS.md")
	if err := os.WriteFile(agents, []byte("# Project\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(filepath.Join(tree, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(agents, filepath.Join(tree, "CLAUDE.md")); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	reportEditableFiles(&report, t.TempDir(), os.Getuid(), DoctorOptions{ConfigDir: configDir})

	got := findings(report, "agent file ownership")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK", got)
	}
}

// A record that cannot be read is not one naming nothing: reporting it as an
// empty enrolment tells an operator with a host of enrolled trees they have
// none, and drops every enrolled agent to n/a beside it.
func TestTreeConfigFailsOnARecordItCannotRead(t *testing.T) {
	configDir := t.TempDir()
	path := filepath.Join(configDir, "enrolled.json")
	if err := os.WriteFile(path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})
	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want one failure", got)
	}
	if !strings.Contains(got[0].Detail, "unknown") {
		t.Errorf("the failure does not say the enrolments are unknown: %s", got[0].Detail)
	}
}

// The instruction files are part of what an enrolment writes: for the
// Antigravity family the rules file plus the account hook is the whole tree
// enrolment, so a tree whose section or frontmatter is gone must not report as
// carrying what init-project wrote.
func TestTreeConfigReportsAStrippedInstructionsFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "antigravity")
	rules := filepath.Join(tree, ".agents", "rules", "faramir.md")
	if err := os.WriteFile(rules, []byte("tidied\n"), 0o640); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})
	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want one warning", got)
	}
	if !strings.Contains(got[0].Detail, rules) {
		t.Errorf("the warning does not name the stripped file: %s", got[0].Detail)
	}
}

// A hand edit that appends a key leaves the file semantically identical and
// not in the merge's normal form; warning that the hook or the rules are
// missing over key order sends an operator hunting for a loss that did not
// happen.
func TestTreeConfigAcceptsAnUnsortedButIntactFile(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.local.json")
	body, err := os.ReadFile(settings)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatal(err)
	}
	doc["zz-model"] = "opus"
	// Marshalled by hand into a non-normal form: unindented, which no merge
	// output is.
	edited, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(settings, edited, 0o640); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeConfig(&report, DoctorOptions{ConfigDir: configDir})
	got := findings(report, "tree config")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Errorf("findings = %+v, want one OK: form is not drift", got)
	}
}

// The mode and the sticky bit are the precondition for the substitution the
// tree check catches only after the fact: group write on an enforcing file is
// the client group rewriting what refuses it, and a directory without sticky
// lets a brokered command rename the file aside whatever its mode.
func TestTreeModesReportsWritableFilesAndUnstickyDirectories(t *testing.T) {
	configDir := t.TempDir()
	tree := enrolTree(t, configDir, "claude")
	settings := filepath.Join(tree, ".claude", "settings.local.json")
	if err := os.Chmod(filepath.Join(tree, ".claude"), 0o770|os.ModeSetgid|os.ModeSticky); err != nil {
		t.Fatal(err)
	}

	var report DoctorReport
	diagnoseTreeModes(&report, DoctorOptions{ConfigDir: configDir})
	got := findings(report, "tree modes")
	if len(got) != 1 || got[0].Status != StatusOK {
		t.Fatalf("findings = %+v, want one OK on an intact tree", got)
	}

	if err := os.Chmod(settings, 0o660); err != nil {
		t.Fatal(err)
	}
	report = DoctorReport{}
	diagnoseTreeModes(&report, DoctorOptions{ConfigDir: configDir})
	got = findings(report, "tree modes")
	if len(got) != 1 || got[0].Status != StatusFailed {
		t.Fatalf("findings = %+v, want a failure on a group-writable hook file", got)
	}
	if !strings.Contains(got[0].Detail, settings) {
		t.Errorf("the failure does not name the file: %s", got[0].Detail)
	}

	if err := os.Chmod(settings, 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(tree, ".claude"), 0o770|os.ModeSetgid); err != nil {
		t.Fatal(err)
	}
	report = DoctorReport{}
	diagnoseTreeModes(&report, DoctorOptions{ConfigDir: configDir})
	got = findings(report, "tree modes")
	if len(got) != 1 || got[0].Status != StatusWarn {
		t.Fatalf("findings = %+v, want a warning on a directory without sticky", got)
	}
}
