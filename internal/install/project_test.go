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
// under ~/.config/sops.  The walk cannot be undone.
func TestOversharingIsRefused(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("no current user to take a home from")
	}
	home := filepath.Clean(me.HomeDir)
	for dir, wantRefused := range map[string]bool{
		"/":                true,
		"/home":            true,
		"/home/someone":    true,
		"/root":            true,
		home:               true,
		filepath.Dir(home): true,
		// The ordinary case, which the refusals must not reach.
		filepath.Join(home, "src/project"): false,
		"/home/someone/src/project":        false,
		"/srv/project":                     false,
	} {
		err := refuseOversharing(dir, me.Username)
		if refused := err != nil; refused != wantRefused {
			t.Errorf("refuseOversharing(%q) refused = %v (%v), want %v",
				dir, refused, err, wantRefused)
		}
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
	_, err = Project(ProjectOptions{Dir: link, OperatorUser: me.Username, DryRun: true})
	if err == nil {
		t.Error("init-project enrolled a symlink pointing at a home")
	}
}
