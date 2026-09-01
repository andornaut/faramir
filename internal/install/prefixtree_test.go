package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/config"
)

// A trailing-wildcard entry reaches an enrolled tree without ever spelling its
// name, and the containment check has to answer for the rule that is rendered
// rather than for the entry as written. filepath.Rel compares path elements, so
// "<home>/pro*" does not hold "<home>/proj" by that reading, while DirUnder's
// subject matches every file in it: the entry was accepted and the agent was
// refused its whole checkout after the reload.
func TestAPrefixEntryReachingAnEnrolledTreeIsRefused(t *testing.T) {
	dir := writeBlockConfig(t, "")
	home := t.TempDir()
	tree := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(tree, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := agentcfg.RecordEnrolment(dir, agentcfg.EnrolledTree{
		Dir: tree, AgentUser: "op", Agents: []string{"claude"},
	}); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct{ name, path string }{
		// Short of the tree's name, which is the spelling that slipped through.
		{"a prefix of the tree's name", filepath.Join(home, "pro") + "*"},
		{"one character of it", filepath.Join(home, "p") + "*"},
		// The whole name with a wildcard after it, which reaches it as surely.
		{"the tree's name and a wildcard", tree + "*"},
		// A prefix of the home that holds it.
		{"a prefix of the home", home + "*"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := AddBlockedPaths(Options{ConfigDir: dir},
				[]config.BlockedPath{{Path: tc.path}})
			if err == nil {
				t.Fatalf("blocked %q, and its rule reaches the enrolled tree", tc.path)
			}
			if !strings.Contains(err.Error(), tree) {
				t.Errorf("error is %q, want it to name the tree", err)
			}
		})
	}

	// A prefix inside the tree is the ordinary entry, and so is one beside it:
	// neither renders a rule over the directory the agent works in.
	for _, path := range []string{
		filepath.Join(tree, ".env") + "*",
		filepath.Join(tree, "sub", "id_") + "*",
		filepath.Join(home, "other") + "*",
	} {
		if err := refuseEnrolledTrees(dir, []string{path}); err != nil {
			t.Errorf("%s was refused, and it reaches no tree: %v", path, err)
		}
	}
}

// coversPath is the one reader of both forms, so what it answers is what the
// refusal above is built on.
func TestCoversPathAnswersForTheRenderedRule(t *testing.T) {
	for _, tc := range []struct {
		entry, inner string
		want         bool
	}{
		// The literal form, unchanged.
		{"/home/op", "/home/op/proj", true},
		{"/home/op", "/home/op", true},
		{"/home/op", "/home/op2/proj", false},
		{"/home/op/proj", "/home/op", false},
		// The prefix form, where the element comparison said no and the rule
		// says yes.
		{"/home/op/pro*", "/home/op/proj", true},
		{"/home/op/proj*", "/home/op/proj", true},
		{"/home/o*", "/home/op/proj", true},
		// And where it reaches nothing: a different name under the same parent.
		{"/home/op/other*", "/home/op/proj", false},
		{"/home/op/projx*", "/home/op/proj", false},
	} {
		if got := coversPath(tc.entry, tc.inner); got != tc.want {
			t.Errorf("coversPath(%q, %q) = %v, want %v",
				tc.entry, tc.inner, got, tc.want)
		}
	}
}
