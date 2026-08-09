package install

import (
	"os/user"
	"path/filepath"
	"strings"
	"testing"
)

const block = snippetBegin + "\nnew text\n" + snippetEnd + "\n"

// Enrolling a project twice must not leave the instructions in it twice.  The
// old recipe appended, which is why this is spliced between markers.
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

// The project's own instructions are not this command's to rewrite: only what
// is between the markers belongs to faramir.
func TestSpliceBlockKeepsSurroundingText(t *testing.T) {
	existing := []byte("# My project\n\nSome rules.\n")
	out := string(spliceBlock(existing, block))
	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
	if !strings.Contains(out, "new text") {
		t.Error("the block was not added")
	}

	// A later version of the snippet replaces the old one in place, rather than
	// leaving the project with two sets of instructions that disagree.
	updated := strings.Replace(block, "new text", "newer text", 1)
	out = string(spliceBlock([]byte(out), updated))
	// Two checks rather than one condition: a splice that added the new text
	// without removing the old one fails only the first, and a conjunction would
	// report neither.
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

// Enrolling a tree walks it granting the client group read and write, and
// faramir-exec is in that group.  For a checkout that is the point; for a home
// it hands every brokered command ~/.ssh and the age key under ~/.config/sops,
// and the walk cannot be undone because the modes it replaced are recorded
// nowhere.
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
		// The ordinary case, and the one the refusals must not reach.
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
