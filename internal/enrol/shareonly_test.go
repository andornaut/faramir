package enrol

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

func TestShareProtectionUsesDeclaredPathsAndPrefixes(t *testing.T) {
	cfg := &config.Config{
		Secret: config.SecretConfig{
			Blocked: []config.BlockedPath{{Path: "/project/private"}, {Path: "/project/token*"}},
			Links:   []config.Link{{Path: "/project/credentials"}},
		},
		Ssh: config.SshConfig{Key: "/project/key"},
	}
	protected, err := shareProtection(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		path string
		want bool
	}{
		{"/project/private", true}, {"/project/private/nested", true},
		{"/project/token-other", true}, {"/project/credentials", true},
		{"/project/key", true}, {"/project/src", false}, {"/project/private-other", false},
	} {
		if got := protected(tc.path); got != tc.want {
			t.Errorf("protected(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}

func TestShareOnlyDryRunWritesNoEnrollmentOrAgentConfiguration(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	group, err := user.LookupGroupId(me.Gid)
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	// The fixture's ancestors, including Go's per-test temporary parent, must
	// permit the selected group to traverse before the sharing preflight runs.
	for path := filepath.Dir(root); path != os.TempDir(); path = filepath.Dir(path) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, info.Mode()|0o010); err != nil {
			t.Fatal(err)
		}
	}
	configDir := installedConfig(t, installed())
	before, err := os.ReadDir(configDir)
	if err != nil {
		t.Fatal(err)
	}
	report, err := ShareOnly(Options{
		Dir: root, AgentUser: me.Username, ClientGroup: group.Name,
		ConfigDir: configDir, DryRun: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if report.Changed || !report.DryRun {
		t.Errorf("dry run reported %+v", report)
	}
	entries, err := os.ReadDir(root)
	if err != nil || len(entries) != 0 {
		t.Errorf("dry run wrote tree entries: %v, %v", entries, err)
	}
	after, err := os.ReadDir(configDir)
	if err != nil || len(before) != len(after) {
		t.Errorf("dry run changed config entries: %v, %v", after, err)
	}
	if _, err := os.Stat(filepath.Join(configDir, "enrolled.json")); !os.IsNotExist(err) {
		t.Errorf("dry run wrote enrollment record: %v", err)
	}
	_, err = ShareOnly(Options{
		Dir: "/", AgentUser: me.Username, ClientGroup: group.Name,
		ConfigDir: configDir, DryRun: true,
	})
	if err == nil || !strings.Contains(err.Error(), "refusing to share") {
		t.Errorf("oversharing returned %v, want share refusal", err)
	}
}
