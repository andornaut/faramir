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

// section is the block's body, as blockIn compares it.
func section(t *testing.T) string {
	t.Helper()
	snippet, err := readAsset("agent/instructions.md.snippet")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(snippet), "\n")
}

// The three signals, strongest first.  Each is sound where the one below it is
// only a guess, which is why they are read in this order rather than any other.
func TestWhatAFileShowsAboutTheBlock(t *testing.T) {
	body := section(t)
	for _, tc := range []struct {
		name    string
		current string
		want    blockState
	}{
		{
			// Nothing to be careful about: write it.
			name: "an empty file", current: "", want: blockMine,
		},
		{
			name:    "a file that has never heard of faramir",
			current: "# Project\n\nSome notes.\n", want: blockMine,
		},
		{
			// The markers are proof: what is between them was put there by this.
			name:    "the block between its markers",
			current: "# Project\n\n" + credentialsBlock(t), want: blockMine,
		},
		{
			// The case an agent asked to tidy the file leaves behind: every word
			// kept, the HTML comment dropped.  Already current, so nothing to do.
			name:    "the block word for word without its markers",
			current: "# Project\n\n" + body + "\n", want: blockCurrent,
		},
		{
			// An older copy of the block, or somebody's own notes about this tool.
			// The two cannot be told apart and both are somebody's writing.
			name:    "an older copy of the block",
			current: "# Credentials\n\nRun things with faramir_run, or so we used to.\n",
			want:    blockForeign,
		},
		{
			name:    "prose that merely mentions the tool",
			current: "# Project\n\nWe use faramir on this host.\n", want: blockForeign,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := blockIn([]byte(tc.current), body); got != tc.want {
				t.Errorf("blockIn = %v, want %v", got, tc.want)
			}
		})
	}
}

// Markers outrank the body: a file carrying both is one this owns, and the
// section between them is replaced rather than left alone as already current.
// Otherwise a snippet that changed would never be updated anywhere.
func TestMarkersOutrankTheBody(t *testing.T) {
	current := []byte("# Project\n\n" + credentialsBlock(t))
	if got := blockIn(current, section(t)); got != blockMine {
		t.Errorf("blockIn = %v, want %v: markers are what make it replaceable", got, blockMine)
	}
}

// The fingerprint has to be in what is shipped, or it recognises nothing: the
// asset and this check drift apart silently otherwise, and the symptom is a
// duplicated block rather than an error.
func TestTheBlockBodyIsWhatIsShipped(t *testing.T) {
	if !strings.Contains(credentialsBlock(t), section(t)) {
		t.Error("the block does not contain the body blockIn compares against")
	}
	if !strings.Contains(strings.ToLower(section(t)), "faramir") {
		t.Error("the body does not mention faramir, so the weakest signal never fires")
	}
}
