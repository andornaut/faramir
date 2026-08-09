package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// sops takes the first .sops.yaml it finds walking up from the working
// directory, so a copy in the store shadows the one in the config directory for
// anything run from in there.  Which of the four states an install is in decides
// what an operator has to do about it, so each has to read differently: the
// remedy for a shadowing copy is to compare the recipients and delete one, and
// the remedy for a stale one alone is to move it.
//
// This is one check the whole of doctor can be tested without: no systemd, no
// accounts, no root.
func TestDiagnoseSopsConfig(t *testing.T) {
	for _, tc := range []struct {
		name    string
		current bool
		stale   bool
		want    Status
		says    []string
	}{
		{
			name: "the rule where it belongs", current: true,
			want: StatusOK, says: []string{"/.sops.yaml"},
		},
		{
			name: "a copy in the store shadows it", current: true, stale: true,
			want: StatusWarn, says: []string{"shadows", "recipients", "rm "},
		},
		{
			name: "only the copy earlier installs left behind", stale: true,
			want: StatusWarn, says: []string{"mv "},
		},
		{
			// Not an error: an install with no creation rule still runs, it just
			// cannot encrypt a new file into the store.
			name: "no rule at all",
			want: StatusWarn, says: []string{"no ", "refuses to encrypt"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			layout := Layout{ConfigDir: dir}
			if tc.current {
				writeRule(t, layout.SopsConfigPath())
			}
			if tc.stale {
				writeRule(t, layout.StaleSopsConfigPath())
			}

			var report DoctorReport
			diagnoseSopsConfig(&report, DoctorOptions{ConfigDir: dir})

			if len(report.Findings) != 1 {
				t.Fatalf("findings = %+v, want exactly one", report.Findings)
			}
			finding := report.Findings[0]
			if finding.Name != "sops config" {
				t.Errorf("check name = %q", finding.Name)
			}
			if finding.Status != tc.want {
				t.Errorf("status = %q, want %q: %s", finding.Status, tc.want, finding.Detail)
			}
			for _, want := range tc.says {
				if !strings.Contains(finding.Detail, want) {
					t.Errorf("detail does not say %q: %s", want, finding.Detail)
				}
			}
			// Warn, never failed: none of these stops the broker serving, and a
			// failed here would make doctor exit non-zero on a working install.
			if report.Failed {
				t.Errorf("a sops rule finding failed the whole report: %s", finding.Detail)
			}
		})
	}
}

func writeRule(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("creation_rules: []\n"), 0o644); err != nil {
		t.Fatal(err)
	}
}
