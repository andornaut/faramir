package install

import (
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostlayout"
)

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
