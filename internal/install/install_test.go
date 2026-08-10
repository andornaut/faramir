package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

// The config directory is the only one faramir creates whose parent can belong
// to the operator, and ensureDir chowns every ancestor it has to create.  An
// absent parent is refused before anything is written rather than coming back
// root-owned.
func TestPreflightRefusesAConfigDirWhoseParentIsAbsent(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator, so it never reaches this check")
	}
	base := t.TempDir()
	for _, tc := range []struct {
		name      string
		configDir string
		refused   bool
	}{
		{"the parent is absent", filepath.Join(base, "absent", "faramir"), true},
		// Reaches the later checks instead, which is all this asserts: the parent
		// being there is not what stops the run.
		{"the parent is there", filepath.Join(base, "faramir"), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			run := &runner{
				opts:   Options{OperatorUser: me.Username, DryRun: true},
				layout: Layout{ConfigDir: tc.configDir},
			}

			err := run.preflight()

			parent := filepath.Dir(tc.configDir)
			refused := err != nil && strings.Contains(err.Error(), parent)
			if refused != tc.refused {
				t.Errorf("preflight() = %v, refused for %s = %v, want %v",
					err, parent, refused, tc.refused)
			}
		})
	}
}
