package enroll

import (
	"os"
	osuser "os/user"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// dryRunProject enrols dir without privilege and without writing, which is the
// only form of the command a test can run: everything else chowns.
func dryRunProject(t *testing.T, dir string) (Report, error) {
	t.Helper()
	if os.Geteuid() == 0 {
		t.Skip("an enrolment refuses root as the operator, so it never reaches this")
	}
	me, err := osuser.Current()
	if err != nil {
		t.Skipf("cannot name this account: %v", err)
	}
	return Tree(Options{
		Dir: dir, AgentUser: me.Username, ClientGroup: "nosuchgroup",
		ConfigDir: t.TempDir(), DryRun: true,
	})
}

// A dry run is what an operator asks a tree about before enrolling it, and the
// first step of a real run is the one that cannot be undone. So it has to write
// nothing at all: not the agent configuration, not the instructions, and not
// the directories either of those would sit in.
//
// Against what the run says it would have written, not against the untouched
// tree alone: a run that refused early, or found no agent to configure, also
// leaves the tree exactly as it was, and this has to tell the two apart.
func TestADryRunEnrolmentLeavesTheTreeExactlyAsItWas(t *testing.T) {
	dir := t.TempDir()
	// A tree carrying an agent's own configuration, so auto has something to
	// find and the run has files to write rather than skipping every step.
	if err := os.MkdirAll(filepath.Join(dir, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	for path, body := range map[string]string{
		"AGENTS.md":                   "# Project\n\nMy own notes.\n",
		".claude/settings.local.json": "{\n  \"model\": \"mine\"\n}\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, path), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	before := treeState(t, dir)

	report, err := dryRunProject(t, dir)

	if err != nil {
		t.Fatalf("a dry run failed: %v\n%+v", err, report)
	}
	if after := treeState(t, dir); after != before {
		t.Errorf("a dry run changed the tree:\nbefore:\n%s\nafter:\n%s", before, after)
	}
	if !report.DryRun {
		t.Error("the report does not say it was a dry run")
	}
	for _, want := range []struct{ step, file string }{
		{"agent config", ".claude/settings.local.json"},
		{"instructions", "AGENTS.md"},
	} {
		if !reportedWriting(report, want.step, want.file) {
			t.Errorf("the report does not say %s would write %s, so the untouched "+
				"tree above says nothing: %+v", want.step, want.file, report.Steps)
		}
	}
}

// reportedWriting is whether the report says this step would change that file,
// which is what makes an untouched tree evidence rather than a coincidence.
func reportedWriting(report Report, step, file string) bool {
	for _, got := range report.Steps {
		if got.Name == step && got.Changed && strings.Contains(got.Detail, file) {
			return true
		}
	}
	return false
}

// The tree being changed is not always the one that was named, and a symlinked
// argument is the case: the walk follows the link with its chmod and chown and
// not with its walk, so the enrolment resolves it first and says which tree it
// landed on. Silently enrolling the target is how a checkout is shared that
// nobody meant to share.
func TestAnEnrolmentSaysWhichTreeALinkResolvedTo(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "project")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	named := filepath.Join(base, "shortcut")
	if err := os.Symlink(target, named); err != nil {
		t.Fatal(err)
	}

	report, err := dryRunProject(t, named)

	if err != nil {
		t.Fatalf("a dry run through a symlink failed: %v", err)
	}
	if report.Dir != target {
		t.Errorf("Dir = %q, want the tree the link resolves to (%q)", report.Dir, target)
	}
	warned := strings.Join(report.Warnings, "\n")
	if !strings.Contains(warned, target) || !strings.Contains(warned, named) {
		t.Errorf("the report does not say which tree is being enrolled:\n%s", warned)
	}
}

// And the same warning is not raised for a path that only had to be made
// absolute. `.`, a relative name and a trailing slash all name the tree the
// operator is standing in, and being told each of them resolves to the tree
// being enrolled says nothing while making the one warning that matters look
// like more of the same.
func TestAnEnrolmentDoesNotWarnAboutMerelyAbsolutingAPath(t *testing.T) {
	base := t.TempDir()
	// The temporary directory may itself sit under a link (/tmp -> /private/tmp
	// and the like), which is a real resolution and would warn for its own
	// reason.
	base, err := filepath.EvalSymlinks(base)
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(base, "project")
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatal(err)
	}
	t.Chdir(base)

	for _, named := range []string{"project", "./project", "project/", target, target + "/", "."} {
		t.Run(named, func(t *testing.T) {
			want := target
			if named == "." {
				want = base
			}
			report, err := dryRunProject(t, named)
			if err != nil {
				t.Fatalf("a dry run of %q failed: %v", named, err)
			}
			if report.Dir != want {
				t.Fatalf("Dir = %q, want %q", report.Dir, want)
			}
			if warned := strings.Join(report.Warnings, "\n"); strings.Contains(warned, "resolves to") {
				t.Errorf("%q warned that it resolves to the tree being enrolled:\n%s", named, warned)
			}
		})
	}
}

// A path that is not a directory is refused by name rather than reported as
// whichever step first fell over it.
func TestAnEnrolmentRefusesAPathThatIsNotADirectory(t *testing.T) {
	base := t.TempDir()
	file := filepath.Join(base, "AGENTS.md")
	if err := os.WriteFile(file, []byte("# Not a tree\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	for _, path := range []string{file, filepath.Join(base, "absent")} {
		if _, err := dryRunProject(t, path); err == nil {
			t.Errorf("%s was enrolled as a tree", path)
		} else if !strings.Contains(err.Error(), path) {
			t.Errorf("err = %v, want it to name %s", err, path)
		}
	}
}

// treeState is every path under dir with its mode and contents, for comparing a
// tree against itself.
func treeState(t *testing.T, dir string) string {
	t.Helper()
	// Read through an os.Root rather than by absolute path: a walk hands the
	// callback a path it resolved a moment earlier, so reading it again follows
	// whatever the name points at now. Rooted reads refuse to leave dir.
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := root.Close(); err != nil {
			t.Error(err)
		}
	}()
	var lines []string
	err = filepath.Walk(dir, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(dir, path)
		if err != nil {
			return err
		}
		line := rel + " " + info.Mode().String()
		if !info.IsDir() {
			body, err := root.ReadFile(rel)
			if err != nil {
				return err
			}
			line += " " + string(body)
		}
		lines = append(lines, line)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	return strings.Join(lines, "\n")
}
