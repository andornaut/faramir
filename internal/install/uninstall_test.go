package install

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/hostunit"
)

func TestUninstallReportsIncompleteCleanup(t *testing.T) {
	for _, tc := range []struct {
		name        string
		state       string
		stopFails   bool
		stateFails  bool
		absent      bool
		pamFails    bool
		fileFails   bool
		reloadFails bool
		want        []string
	}{
		{name: "stopped", state: "inactive"},
		{name: "failed service is stopped", state: "failed", stateFails: true},
		{name: "already absent", state: "inactive", stateFails: true, stopFails: true, absent: true},
		{name: "stop failed", state: "inactive", stopFails: true, want: []string{"stop failed"}},
		{name: "still active", state: "active", want: []string{"state \"active\""}},
		{name: "still stopping", state: "deactivating", want: []string{"state \"deactivating\""}},
		{name: "unknown", state: "unknown", stateFails: true, want: []string{"state \"unknown\""}},
		{name: "unavailable", stateFails: true, want: []string{"could not verify"}},
		{name: "active query failed", state: "active", stateFails: true, want: []string{"could not verify"}},
		{name: "PAM removal failed", state: "inactive", pamFails: true, want: []string{"shared PAM stack", "PAM removal failed"}},
		{name: "independent failures", state: "active", stopFails: true, pamFails: true, fileFails: true, reloadFails: true,
			want: []string{"stop failed", "state \"active\"", "PAM removal failed", "removal failed", "reload failed"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			previousRunning, previousUnitDir := hostunit.Running, hostunit.SystemUnitDir
			hostunit.Running = func() bool { return true }
			hostunit.SystemUnitDir = dir
			t.Cleanup(func() {
				hostunit.Running, hostunit.SystemUnitDir = previousRunning, previousUnitDir
			})
			units := append(slices.Clone(hostunit.Sockets), hostunit.Services...)
			if !tc.absent {
				for _, unit := range units {
					if err := os.WriteFile(filepath.Join(dir, unit), nil, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			log := filepath.Join(dir, "calls")
			t.Setenv("UNINSTALL_CALLS", log)
			t.Setenv("UNINSTALL_STATE", tc.state)
			for key, fails := range map[string]bool{
				"UNINSTALL_STOP_FAILS": tc.stopFails, "UNINSTALL_STATE_FAILS": tc.stateFails,
				"UNINSTALL_RELOAD_FAILS": tc.reloadFails,
			} {
				value := "0"
				if fails {
					value = "1"
				}
				t.Setenv(key, value)
			}
			const script = `#!/bin/sh
echo "$*" >> "$UNINSTALL_CALLS"
case "$1" in
disable)
  if [ "$UNINSTALL_STOP_FAILS" = 1 ]; then echo 'stop failed' >&2; exit 1; fi ;;
is-active)
  printf '%s\n' "$UNINSTALL_STATE"
  if [ "$UNINSTALL_STATE_FAILS" = 1 ]; then exit 3; fi ;;
daemon-reload)
  if [ "$UNINSTALL_RELOAD_FAILS" = 1 ]; then echo 'reload failed' >&2; exit 1; fi ;;
*) exit 2 ;;
esac
`
			if err := os.WriteFile(filepath.Join(dir, "systemctl"), []byte(script), 0o700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("PATH", dir)
			var removed []string
			remove := func(path string) error {
				removed = append(removed, path)
				if tc.fileFails {
					return errors.New("removal failed")
				}
				if tc.absent {
					return os.ErrNotExist
				}
				return nil
			}
			ops := uninstallOps{
				remove: remove,
				removeAll: func(path string) error {
					removed = append(removed, path)
					if tc.fileFails {
						return errors.New("removal failed")
					}
					return nil
				},
				removeBlock: func() error {
					if tc.pamFails {
						return errors.New("PAM removal failed")
					}
					return nil
				},
			}
			left, err := uninstall(ops, dir)
			if len(tc.want) == 0 && err != nil {
				t.Fatalf("successful uninstall: %v", err)
			}
			for _, want := range tc.want {
				if err == nil || !strings.Contains(err.Error(), want) {
					t.Errorf("error = %v, want %q", err, want)
				}
			}
			kept := strings.Join(left, "\n")
			for _, want := range []string{dir, "age.key", "secrets", "audit log", "users ", "agent configuration", "account-wide configuration"} {
				if !strings.Contains(kept, want) {
					t.Errorf("retained state omits %q: %s", want, kept)
				}
			}
			for _, path := range append(removedPathsForTest(), filepath.Join(hostlayout.DefaultBinDir, "faramir")) {
				if !slices.Contains(removed, path) {
					t.Errorf("independent removal skipped: %s", path)
				}
			}
			calls, readErr := os.ReadFile(log)
			if readErr != nil {
				t.Fatal(readErr)
			}
			for _, unit := range units {
				for _, command := range []string{"disable --now ", "is-active "} {
					if !strings.Contains(string(calls), command+unit+"\n") {
						t.Errorf("skipped %s%s", command, unit)
					}
				}
			}
			if !strings.Contains(string(calls), "daemon-reload\n") {
				t.Error("daemon-reload was skipped")
			}
		})
	}
}

func removedPathsForTest() []string {
	paths := removed()
	for _, unit := range hostunit.Services {
		paths = append(paths, filepath.Join(hostunit.SystemUnitDir, unit), filepath.Join(hostunit.SystemUnitDir, unit+".d"))
	}
	return paths
}

// What an uninstall must not take with it. Each is something the command's own
// report names as left behind, and the age key is the one that cannot be undone:
// deleting it makes every managed sops file unreadable, retroactively.
//
// The directories as well as the files in them. os.RemoveAll on a parent is how
// this goes wrong, and it goes wrong in silence, the report still saying the key
// was kept.
func preservedPaths() []string {
	return []string{
		hostlayout.DefaultConfigDir,
		hostlayout.DefaultConfigDir + "/age.key",
		hostlayout.DefaultConfigDir + "/secrets",
		hostlayout.DefaultConfigDir + "/config.toml",
		hostlayout.DefaultLogDir,
		hostlayout.DefaultLogDir + "/audit.log",
	}
}

// takes reports whether removing path takes target with it: the same path, or a
// directory target sits under.
func takes(path, target string) bool {
	return path == target || strings.HasPrefix(target, path+"/")
}

// removed is every path Uninstall deletes outright.
func removed() []string {
	return append(uninstallPaths(), uninstallDirs()...)
}

// The config directory and the audit log survive an uninstall, which is what the
// command reports and what operating.md promises. A removal path that is one of
// them, or a directory one of them sits under, breaks that promise however the
// list was written, so the rule is checked against the list rather than against
// any one entry in it.
func TestUninstallLeavesTheConfigDirectory(t *testing.T) {
	for _, path := range removed() {
		for _, preserved := range preservedPaths() {
			if takes(path, preserved) {
				t.Errorf("uninstall removes %s, which takes %s with it", path, preserved)
			}
		}
	}
}

// And the guard above is only worth something if it would catch the mistake it
// names, so the mistake is made here and has to be caught. The middle case is the
// one to watch: a fixed path under the config directory reads as a file of
// faramir's own and removes the secret store.
func TestTheConfigDirectoryGuardCatchesADirectoryForm(t *testing.T) {
	for _, path := range []string{hostlayout.DefaultConfigDir, hostlayout.DefaultConfigDir + "/", "/etc"} {
		caught := false
		for _, preserved := range preservedPaths() {
			if takes(strings.TrimSuffix(path, "/"), preserved) {
				caught = true
			}
		}
		if !caught {
			t.Errorf("removing %s was not reported as taking the config with it", path)
		}
	}
}

// The grant's environment file goes with the grant. It holds what the sudoers
// entry handed sudo and names the operator's account, so a host that keeps it
// after an uninstall keeps a file nothing reads and nothing rewrites.
//
// Covered by the libexec directory rather than named on its own, which is the
// reason it lives there: a file this install renders for its own use needs no
// removal entry of its own.
func TestUninstallRemovesTheSudoEnvironmentFile(t *testing.T) {
	sudoEnv := hostlayout.Layout{ConfigDir: hostlayout.DefaultConfigDir, LibexecDir: hostlayout.DefaultLibexecDir}.SudoEnvFile()
	if slices.ContainsFunc(removed(), func(path string) bool { return takes(path, sudoEnv) }) {
		return
	}
	t.Errorf("uninstall leaves %s behind", sudoEnv)
}
