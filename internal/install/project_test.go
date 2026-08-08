package install

import (
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
	if strings.Contains(out, "new text\n") && !strings.Contains(out, "newer text") {
		t.Error("the block was not replaced")
	}
	if strings.Count(out, snippetBegin) != 1 {
		t.Errorf("the block appears more than once:\n%s", out)
	}
	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
}
