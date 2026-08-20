package install

import (
	"os"
	"os/user"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/sharetree"
)

// Enrolling grants the client group read and write on the whole tree, and
// faramir-exec is in that group: for a home that is ~/.ssh and the age key
// under ~/.config/sops. The walk cannot be undone.
func TestOversharingIsRefused(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user to take a home from")
	}
	home := filepath.Clean(me.HomeDir)
	for _, tc := range []struct {
		dir         string
		wantRefused bool
	}{
		{"/", true},
		{"/home", true},
		{"/home/someone", true},
		{"/root", true},
		{home, true},
		{filepath.Dir(home), true},
		// The system directories. Sharing chowns the directory to the operator,
		// chmods it 2770 and applies g+rwX to everything under it, so one of these
		// walked is a host repaired from outside faramir or not at all.
		{"/etc", true},
		{"/usr", true},
		{"/usr/local", true},
		{"/var", true},
		{"/opt", true},
		{"/srv", true},
		{"/tmp", true},
		// The ordinary case, which the refusals must not reach. A project inside a
		// system directory is still a project: a checkout on shared storage is a
		// tree an operator may enrol, needing the ReadWritePaths= drop-in that
		// sharing warns about.
		{filepath.Join(home, "src/project"), false},
		{"/home/someone/src/project", false},
		{"/srv/project", false},
		{"/opt/checkouts/project", false},
	} {
		err := refuseOversharing(tc.dir, me.Username)
		if refused := err != nil; refused != tc.wantRefused {
			t.Errorf("refuseOversharing(%q) refused = %v (%v), want %v",
				tc.dir, refused, err, tc.wantRefused)
		}
	}
}

// faramir's own directories, which the systemRoots list does not name: the age
// key is 0400 and keeper-owned until a walk regroups it, and the client group
// faramir-exec is in would then read the key that opens every managed file.
func TestEnrollingFaramirsOwnDirectoriesIsRefused(t *testing.T) {
	const configDir = "/etc/faramir"
	for _, tc := range []struct {
		dir         string
		wantRefused bool
	}{
		{configDir, true},
		{configDir + "/secrets", true},
		// Above it, which the walk reaches on its way down.
		{"/etc", true},
		// What every hook and plugin execs, and where the deny list lives.
		{DefaultBinDir, true},
		{DefaultLibexecDir, true},
		{DefaultLogDir, true},
		// The ordinary case, which none of the refusals may reach.
		{"/home/someone/src/project", false},
		{"/srv/project", false},
	} {
		err := refuseInstallDirs(tc.dir, configDir)
		if refused := err != nil; refused != tc.wantRefused {
			t.Errorf("refuseInstallDirs(%q) refused = %v (%v), want %v",
				tc.dir, refused, err, tc.wantRefused)
		}
	}
}

// A config moved under a home is where no fixed list of system directories can
// answer, and is exactly the placement the install supports.
func TestEnrollingAConfigDirUnderAHomeIsRefused(t *testing.T) {
	const configDir = "/home/op/.config/faramir"
	for _, dir := range []string{configDir, "/home/op/.config", configDir + "/secrets"} {
		if err := refuseInstallDirs(dir, configDir); err == nil {
			t.Errorf("refuseInstallDirs(%q) with the config at %s was not refused",
				dir, configDir)
		}
	}
	// The positive control: the operator's checkout beside it is still enrollable.
	if err := refuseInstallDirs("/home/op/src/project", configDir); err != nil {
		t.Errorf("an ordinary tree was refused: %v", err)
	}
}

// Chmod and Chown follow a symlink and WalkDir does not, so a symlinked
// argument rewrites what it points at, walks nothing, and reports success.
// Every check is against the resolved path.
func TestOversharingIsRefusedThroughASymlink(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user to take a home from")
	}
	link := filepath.Join(t.TempDir(), "link")
	if err := os.Symlink(me.HomeDir, link); err != nil {
		t.Skip("cannot create a symlink here")
	}
	resolved, err := sharetree.Resolve(link)
	if err != nil {
		t.Fatal(err)
	}
	if err := refuseOversharing(resolved, me.Username); err == nil {
		t.Errorf("a symlink to %s resolved to %s and was not refused", me.HomeDir, resolved)
	}
	// And the whole command, where the resolution has to happen.
	_, err = Project(ProjectOptions{Dir: link, AgentUser: me.Username, DryRun: true})
	if err == nil {
		t.Error("init-project enrolled a symlink pointing at a home")
	}
}
