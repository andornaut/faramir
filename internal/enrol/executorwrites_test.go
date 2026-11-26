package enrol

import (
	"strings"
	"testing"
)

func TestSharingWriteAdvisoryDescribesGeneratedDefaults(t *testing.T) {
	for _, tc := range []struct {
		name          string
		dir           string
		installedSudo bool
		wantWarning   bool
	}{
		{"strict outside home", "/srv/project", false, true},
		{"strict root home", "/root/project", false, true},
		{"similar prefix is outside", "/home-other/project", false, true},
		{"unit-managed path is conditional", "/tmp/project", false, true},
		{"generated home allowance", "/home/operator/project", false, false},
		{"sudo outside home", "/srv/project", true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := project{
				opts:          Options{Dir: tc.dir, DryRun: true},
				installedSudo: tc.installedSudo,
			}
			if err := run.shareTree(); err != nil {
				t.Fatal(err)
			}
			if got := len(run.report.Warnings); (got != 0) != tc.wantWarning {
				t.Fatalf("warnings = %v, want warning %v", run.report.Warnings, tc.wantWarning)
			}
			if !tc.wantWarning {
				return
			}
			warning := strings.Join(run.report.Warnings, "\n")
			for _, want := range []string{tc.dir, "may not", "without --allow-sudo", "generated", "other unit-managed writable paths", "effective unit", "operator drop-ins", "ReadWritePaths= only if needed"} {
				if !strings.Contains(warning, want) {
					t.Errorf("warning %q does not explain %q", warning, want)
				}
			}
			if strings.Contains(warning, "fail with EROFS") {
				t.Errorf("warning claims an unobserved write failure: %s", warning)
			}
		})
	}
}
