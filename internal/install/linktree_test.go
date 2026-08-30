package install

import (
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// A linked path renders the same subject a blocked one does, covering the path
// and everything under it. So an entry naming an enrolled tree refuses the agent
// every file in the directory it works in, whichever command wrote it, and both
// commands have to say so before writing.
func TestALinkNamingAnEnrolledTreeIsRefused(t *testing.T) {
	dir := writeBlockConfig(t, "")
	tree := t.TempDir()
	if err := recordEnrolment(dir, EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}

	_, _, err := AddLink(Options{ConfigDir: dir}, config.Link{
		Ref: "a/b", Path: tree, Type: "json", Key: "k",
	})
	if err == nil {
		t.Fatal("a link naming an enrolled tree was accepted, and it refuses the " +
			"agent every file in the tree it works in")
	}
	if !strings.Contains(err.Error(), "enrolled tree") {
		t.Errorf("the refusal does not say why: %v", err)
	}

	// And the ordinary entry is what this must not get in the way of: a file
	// inside a tree is exactly what a link is usually for. Asked of the rule
	// rather than through AddLink, which goes on to check an install this test
	// does not have.
	if err := refuseEnrolledTrees(dir, []string{tree + "/.env"}); err != nil {
		t.Errorf("a file inside an enrolled tree was refused: %v", err)
	}
}

// The two forms are held to the same rule, so a tree refused to one is refused
// to the other. Asserted as a pair, so a guard added to one and not the other
// fails here.
func TestBothFormsRefuseAnEnrolledTree(t *testing.T) {
	dir := writeBlockConfig(t, "")
	tree := t.TempDir()
	if err := recordEnrolment(dir, EnrolledTree{Dir: tree, AgentUser: "op"}); err != nil {
		t.Fatal(err)
	}

	_, _, blockErr := AddBlockedPaths(Options{ConfigDir: dir},
		[]config.BlockedPath{{Path: tree}})
	_, _, linkErr := AddLink(Options{ConfigDir: dir},
		config.Link{Ref: "a/b", Path: tree, Type: "json", Key: "k"})

	if (blockErr != nil) != (linkErr != nil) {
		t.Errorf("block refused = %v, link refused = %v: both render the same "+
			"subject over the tree and must agree", blockErr != nil, linkErr != nil)
	}
	if blockErr == nil {
		t.Error("neither form refused an enrolled tree")
	}
}
