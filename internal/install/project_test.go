package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/sharetree"
)

const block = snippetBegin + "\nnew text\n" + snippetEnd + "\n"

// Enrolling twice must not leave the instructions in twice, which is what the
// markers are for.
func TestSpliceBlockIsIdempotent(t *testing.T) {
	once := spliceBlock(nil, block)
	twice := spliceBlock(once, block)
	if string(once) != string(twice) {
		t.Errorf("a second enrolment changed the file:\n%q\n%q", once, twice)
	}
	if strings.Count(string(twice), snippetBegin) != 1 {
		t.Errorf("the block appears more than once:\n%s", twice)
	}
}

// Only what is between the markers belongs to faramir.
func TestSpliceBlockKeepsSurroundingText(t *testing.T) {
	existing := []byte("# My project\n\nSome rules.\n")
	out := string(spliceBlock(existing, block))
	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
	if !strings.Contains(out, "new text") {
		t.Error("the block was not added")
	}

	// Replaced in place, not left as two sets that disagree.
	updated := strings.Replace(block, "new text", "newer text", 1)
	out = string(spliceBlock([]byte(out), updated))
	// Two checks: a splice that added without removing fails only the first.
	if strings.Contains(out, "new text\n") {
		t.Errorf("the superseded text survived:\n%s", out)
	}
	if !strings.Contains(out, "newer text") {
		t.Errorf("the block was not replaced:\n%s", out)
	}
	if strings.Count(out, snippetBegin) != 1 {
		t.Errorf("the block appears more than once:\n%s", out)
	}
	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
}

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
