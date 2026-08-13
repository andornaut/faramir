package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installedConfig writes what `init` would have written into a directory an
// enrolment can be pointed at, and answers with that directory.  Rendered from
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
// the path is wrong.  The error names all three.
func TestAMissingConfigStopsTheEnrolment(t *testing.T) {
	_, err := resolved(t, t.TempDir(), "")
	if err == nil {
		t.Fatal("an enrolment with no config to read was allowed to proceed")
	}
	for _, want := range []string{"faramir init", "--config-dir", "--client-group"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %s as a way out: %v", want, err)
		}
	}
}

// --client-group names an install that need not be on this machine, so a config
// that cannot be read is what the flag is for rather than a failure.
func TestANamedGroupEnrolsWithNoConfigToRead(t *testing.T) {
	run, err := resolved(t, t.TempDir(), "elsewhere")
	if err != nil {
		t.Fatal(err)
	}
	if run.report.ClientGroup != "elsewhere" {
		t.Errorf("group = %q, want the one named", run.report.ClientGroup)
	}
	if run.allowSudo {
		t.Error("a tree enrolled against an install this host has no config for was " +
			"told this host's sudo grant")
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
			"agent here is not told to wait for an approval that will happen")
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
