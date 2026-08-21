package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installedConfig writes what `init` would have written into a directory an
// enrolment can be pointed at, and answers with that directory. Rendered from
// the shipped template rather than hand-written, so what is read here is what a
// host actually carries.
func installedConfig(t *testing.T, layout Layout) string {
	t.Helper()
	body, err := render("etc/config.toml.tmpl", layout)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "config.toml"), body, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// resolved runs the group resolution against a config directory and returns the
// enrolment it decided on.
func resolved(t *testing.T, configDir, clientGroup string) (*project, error) {
	t.Helper()
	run := &project{opts: ProjectOptions{ConfigDir: configDir, ClientGroup: clientGroup}}
	return run, run.resolveGroup()
}

// The ordinary path: the group and the grant both come off the installed
// config, which is the config that governs this tree.
func TestTheGroupAndTheGrantAreReadFromTheInstalledConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		layout    Layout
		wantSudo  bool
		wantGroup string
	}{
		{"a host with a sudo grant", sudoGrantLayout(t), true, "shared"},
		{"a host without one", testLayout(), false, "shared"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run, err := resolved(t, installedConfig(t, tc.layout), "")
			if err != nil {
				t.Fatal(err)
			}
			if run.report.ClientGroup != tc.wantGroup {
				t.Errorf("group = %q, want %q", run.report.ClientGroup, tc.wantGroup)
			}
			if run.allowSudo != tc.wantSudo {
				t.Errorf("allowSudo = %v, want %v", run.allowSudo, tc.wantSudo)
			}
		})
	}
}

// A config that is present and will not load is an error rather than something
// to enrol around: this runs as root against a 0644 file, so the ways it fails
// are that faramir is not installed here, that the config is elsewhere, or that
// the path is wrong. The error names all three.
func TestAMissingConfigStopsTheEnrolment(t *testing.T) {
	_, err := resolved(t, t.TempDir(), "")
	if err == nil {
		t.Fatal("an enrolment with no config to read was allowed to proceed")
	}
	for _, want := range []string{"faramir init", "--config-dir"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s as a way out: %v", want, err)
		}
	}
}

// --client-group overrides the group and does not stand in for the file. An
// enrolment writes this install's deny rules into the tree, and the linked and
// blocked paths among them are only in the config: a tree enrolled without it
// would carry a list naming the built-in paths and not the credential file this
// install added, which reads exactly like one that covers everything.
func TestANamedGroupStillNeedsAConfigToRead(t *testing.T) {
	if _, err := resolved(t, t.TempDir(), "elsewhere"); err == nil {
		t.Fatal("a named group enrolled a tree against no config at all")
	}
}

// A dry run writes nothing, so it has no incomplete rules to prevent: asking
// about a tree from a host that has not been provisioned yet is what it is for.
func TestADryRunReportsOnATreeWithNoConfigToRead(t *testing.T) {
	run := &project{opts: ProjectOptions{
		ConfigDir: t.TempDir(), ClientGroup: "elsewhere", DryRun: true,
	}}
	if err := run.resolveGroup(); err != nil {
		t.Fatalf("a dry run against an unprovisioned host was refused: %v", err)
	}
	if run.report.ClientGroup != "elsewhere" {
		t.Errorf("group = %q, want the one named", run.report.ClientGroup)
	}
	if run.allowSudo {
		t.Error("a tree reported on with no config to read was described using a " +
			"sudo grant nothing established")
	}
	if len(run.report.Warnings) == 0 {
		t.Error("a dry run that could not read the config said so nowhere")
	}
}

// The grant is this host's to report only where this host's config admits the
// group just named, which is what says the flag named this install rather than
// another one.
func TestTheGrantIsReadOnlyWhereTheNamedGroupIsThisInstalls(t *testing.T) {
	configDir := installedConfig(t, sudoGrantLayout(t))

	same, err := resolved(t, configDir, "shared")
	if err != nil {
		t.Fatal(err)
	}
	if !same.allowSudo {
		t.Error("naming this install's own group withheld its sudo grant, so an " +
			"agent here is not told to wait for an escalation that will happen")
	}

	other, err := resolved(t, configDir, "somebody-elses")
	if err != nil {
		t.Fatal(err)
	}
	if other.allowSudo {
		t.Error("a tree enrolled for another install was described using this " +
			"host's sudo grant")
	}
}
