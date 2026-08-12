package install

import (
	"strings"
	"testing"
)

// block is the credentials section as instructions() writes it.
func credentialsBlock(t *testing.T) string {
	t.Helper()
	snippet, err := readAsset("agent/instructions.md.snippet")
	if err != nil {
		t.Fatal(err)
	}
	return snippetBegin + "\n" + strings.TrimRight(string(snippet), "\n") + "\n" + snippetEnd + "\n"
}

// The ordinary case: markers there, block replaced between them, once.
func TestTheBlockIsReplacedBetweenItsMarkers(t *testing.T) {
	current := "# Project\n\nSome notes.\n\n" + credentialsBlock(t) + "\n## After\n"
	got := string(spliceBlock([]byte(current), credentialsBlock(t)))

	if n := strings.Count(got, snippetBegin); n != 1 {
		t.Errorf("%d copies of the block, want 1", n)
	}
	for _, want := range []string{"Some notes.", "## After"} {
		if !strings.Contains(got, want) {
			t.Errorf("splicing lost %q:\n%s", want, got)
		}
	}
}

// A file with neither the block nor the markers gets it appended, and keeps
// what was there.
func TestTheBlockIsAppendedToAFileThatLacksIt(t *testing.T) {
	got := string(spliceBlock([]byte("# Project\n\nSome notes.\n"), credentialsBlock(t)))

	if !strings.Contains(got, "Some notes.") || !strings.Contains(got, snippetBegin) {
		t.Errorf("append lost the file or the block:\n%s", got)
	}
}

// The case an operator reaches by asking an agent to tidy the file: every word
// of the block is still there and the markers, being an HTML comment, are not.
// Appending would leave two copies of the instructions, so this is recognised
// by the block's own content instead.
func TestTheBlockIsRecognisedWithoutItsMarkers(t *testing.T) {
	stripped := strings.NewReplacer(snippetBegin, "", snippetEnd, "").Replace(credentialsBlock(t))
	current := []byte("# Project\n\n" + stripped)

	if !unmarked(current) {
		t.Error("a marker-less copy of the block was not recognised")
	}
	// And the ordinary states are not mistaken for it, or an enrolment would
	// stop doing its job on every tree.
	if unmarked([]byte(credentialsBlock(t))) {
		t.Error("a properly marked block was reported as unmarked")
	}
	if unmarked([]byte("# Project\n\nSome notes.\n")) {
		t.Error("a file with no block at all was reported as carrying one")
	}
	if unmarked(nil) {
		t.Error("an absent file was reported as carrying the block")
	}
}

// The fingerprint has to be in what is shipped, or it recognises nothing: the
// asset and this check drift apart silently otherwise, and the symptom is a
// duplicated block rather than an error.
func TestTheFingerprintIsInTheShippedSnippet(t *testing.T) {
	snippet, err := readAsset("agent/instructions.md.snippet")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(snippet), snippetFingerprint) {
		t.Errorf("the snippet does not contain %q, so nothing recognises a "+
			"marker-less copy of it", snippetFingerprint)
	}
}
