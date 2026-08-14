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
				opts:   Options{AgentUser: me.Username, DryRun: true},
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

// A symlink where the install asserts a mode or an owner would apply it to the
// target instead.  Refused before anything is written, so the answer is one
// message and an untouched host rather than a run that dies with the accounts
// created and no units.
func TestPreflightRefusesASymlinkedPath(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator, so it never reaches this check")
	}
	for _, tc := range []struct {
		name string
		// link is relative to the config directory; "" puts it at LogDir instead.
		link  string
		isDir bool
		inLog string
	}{
		{name: "a drop-in", link: "config.d/local.toml"},
		{name: "the drop-in directory", link: "config.d", isDir: true},
		{name: "a managed secrets file", link: "secrets/prod.sops.yml"},
		{name: "the secrets directory", link: "secrets", isDir: true},
		{name: "the creation rule", link: ".sops.yaml"},
		{name: "the age key", link: "age.key"},
		{name: "the audit log", inLog: "audit.log"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			configDir := filepath.Join(base, "faramir")
			logDir := filepath.Join(base, "log")
			for _, dir := range []string{
				configDir, logDir,
				filepath.Join(configDir, "config.d"), filepath.Join(configDir, "secrets"),
			} {
				if err := os.MkdirAll(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			}
			// Somewhere the link can point that is not where it sits.
			target := filepath.Join(base, "elsewhere")
			if tc.isDir {
				if err := os.MkdirAll(target, 0o755); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
				t.Fatal(err)
			}
			link := filepath.Join(configDir, tc.link)
			if tc.inLog != "" {
				link = filepath.Join(logDir, tc.inLog)
			}
			if tc.isDir {
				if err := os.RemoveAll(link); err != nil {
					t.Fatal(err)
				}
			}
			if err := os.Symlink(target, link); err != nil {
				t.Fatal(err)
			}

			run := &runner{
				opts: Options{AgentUser: me.Username, DryRun: true},
				layout: Layout{ConfigDir: configDir, LogDir: logDir,
					AgeKeyPath: filepath.Join(configDir, "age.key")},
			}

			err := run.preflight()
			if err == nil {
				t.Fatal("the run was allowed to start with a symlink in the tree")
			}
			if !strings.Contains(err.Error(), link) {
				t.Errorf("error does not name %s: %v", link, err)
			}
			if !strings.Contains(err.Error(), target) {
				t.Errorf("error does not say where the link points: %v", err)
			}
		})
	}
}

// Nothing linked, so the symlink check is not what stops the run.
func TestPreflightAllowsATreeWithNoSymlinks(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("preflight refuses root as the operator")
	}
	base := t.TempDir()
	configDir := filepath.Join(base, "faramir")
	logDir := filepath.Join(base, "log")
	for _, dir := range []string{
		configDir, logDir,
		filepath.Join(configDir, "config.d"), filepath.Join(configDir, "secrets"),
	} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(configDir, "config.d", "local.toml"),
		[]byte("# x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		opts:   Options{AgentUser: me.Username, DryRun: true},
		layout: Layout{ConfigDir: configDir, LogDir: logDir},
	}
	if err := run.refuseSymlinks(); err != nil {
		t.Errorf("refuseSymlinks() = %v, want nil for a tree with no links", err)
	}
}
