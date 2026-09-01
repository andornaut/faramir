package agentcfg

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/hostfs"
)

// The four placements, and what each one licenses. The markers are what makes
// a block replaceable: what is between them is faramir's whatever it now says,
// and everything outside them is somebody else's.
func TestWhereTheSectionGoes(t *testing.T) {
	body := section(t)
	wrapped := sectionBlock(body)
	// An unmarked older copy is found by the shipped section's own heading, so
	// the cases that turn on one derive it rather than spelling it out.
	heading, _, _ := strings.Cut(body, "\n")
	for _, tc := range []struct {
		name    string
		current string
		want    sectionPlacement
	}{
		{"an empty file", "", placeAppend},
		{"no sign of faramir", "# Project\n\nSome notes.\n", placeAppend},
		{
			// Naming the tool is not carrying a section: what delimits one is the
			// markers, so this file gets a block appended like any other.
			"prose that merely mentions the tool",
			"# Project\n\nWe use faramir on this host.\n",
			placeAppend,
		},
		{"a delimited block", "# Project\n\n" + wrapped + "\n", placeReplace},
		{
			// Not word for word what is written now, and replaced regardless.
			"a delimited block that says something else",
			SectionBegin + "\n# Credentials\n\nWhatever the last version said.\n" + SectionEnd + "\n",
			placeReplace,
		},
		{"the section with its markers stripped", "# Project\n\n" + body, placeWrap},
		{"the section and nothing else, unmarked", body, placeWrap},
		{
			// The wrap matches the text exactly, so a copy reworded past that is
			// one it cannot delimit. Appending would leave two sets of
			// credentials instructions contradicting each other.
			"an unmarked section in words that are not these",
			"# Project\n\n" + heading + "\n\nRun things with faramir run, or so we used to.\n",
			placeStale,
		},
		// Both signs are needed to call a file stale: a heading of somebody's own
		// is not this section, and merely naming the tool is the case the markers
		// exist to unblock.
		{"the heading with no mention of the tool", "# Project\n\n" + heading + "\n\nMy own keys.\n", placeAppend},
		{"a begin with no end", SectionBegin + "\n" + body, placeRefuse},
		{"an end with no begin", body + SectionEnd + "\n", placeRefuse},
		{"the markers inverted", SectionEnd + "\n" + body + SectionBegin + "\n", placeRefuse},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _ := placeSection([]byte(tc.current), body)
			if got != tc.want {
				t.Errorf("placeSection = %v, want %v", got, tc.want)
			}
		})
	}
}

// A block already written is replaced by what is written now, which is what the
// markers are for: an updated snippet reaches a tree that was enrolled against
// an older one.
func TestAnUpdatedSectionReplacesTheOldOne(t *testing.T) {
	body := section(t)
	stale := "# Project\n\n" + SectionBegin + "\n# Credentials\n\nOld words.\n" + SectionEnd + "\n"

	place, start, end := placeSection([]byte(stale), body)
	out := string(writeSection([]byte(stale), body, place, start, end))

	if strings.Contains(out, "Old words.") {
		t.Errorf("the stale block survived:\n%s", out)
	}
	if !strings.Contains(out, body) {
		t.Errorf("the current section was not written:\n%s", out)
	}
	if !strings.HasPrefix(out, "# Project\n\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
}

// An empty file gets the block and no leading blank line.
func TestAnEmptyFileGetsTheSectionAlone(t *testing.T) {
	body := section(t)
	want := sectionBlock(body) + "\n"
	for _, current := range []string{"", "\n\n"} {
		if got := string(writeInstructions(t, []byte(current), body)); got != want {
			t.Errorf("a file of %q got %q, want %q", current, got, want)
		}
	}
}

// Changing the shipped snippet must not give an already-enrolled tree a second
// section. The wording changes; the heading is what an older copy is found by,
// so a change that drops it silently turns every such file into a duplicate.
func TestARewordedSectionIsNeverAppendedBesideTheOldOne(t *testing.T) {
	body := section(t)
	heading, _, ok := strings.Cut(body, "\n")
	if !ok || !strings.HasPrefix(heading, "#") {
		t.Fatalf("the section does not open with a heading (%q), which is what an "+
			"older copy of it is recognised by", heading)
	}
	// What an earlier snippet left behind: this heading, this tool, other words.
	older := "# My project\n\n" + heading + "\n\nWhatever the last version said about " +
		"faramir run.\n"

	place, _, _ := placeSection([]byte(older), body)
	if place != placeStale {
		t.Errorf("placeSection = %v, want %v: an older section would be left in "+
			"place beside a new one", place, placeStale)
	}
}

// faramir owns the block between the markers, not the file it sits in, and the
// block is documentation rather than something enforcement rests on. So an
// instructions file that is already there keeps the mode it has, and only one
// this creates is given one.
func TestAnExistingInstructionsFileKeepsItsMode(t *testing.T) {
	dir := t.TempDir()
	body := section(t)

	kept := filepath.Join(dir, "AGENTS.md")
	const theirs = os.FileMode(0o644)
	if err := os.WriteFile(kept, []byte("# My project\n"), theirs); err != nil {
		t.Fatal(err)
	}
	if _, err := SectionFile(hostfs.FS{}, kept, body, "", hostfs.Keep, hostfs.Keep, ""); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(kept)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != theirs {
		t.Errorf("mode = %04o, want the %04o it already had: faramir owns the "+
			"section, not the file", got, theirs)
	}

	// A file this creates has no mode of its own to keep.
	made := filepath.Join(dir, "CLAUDE.md")
	if _, err := SectionFile(hostfs.FS{}, made, body, "", hostfs.Keep, hostfs.Keep, ""); err != nil {
		t.Fatal(err)
	}
	info, err = os.Stat(made)
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != instructionsMode {
		t.Errorf("a created file got mode %04o, want %04o", got, os.FileMode(instructionsMode))
	}
}

// writeInstructions is instructions()'s file handling without the filesystem.
func writeInstructions(t *testing.T, current []byte, body string) []byte {
	t.Helper()
	place, start, end := placeSection(current, body)
	if place == placeRefuse {
		t.Fatalf("placeSection refused:\n%s", current)
	}
	return writeSection(current, body, place, start, end)
}

// The rules both sections state are one asset rendered into each, so a home and
// a tree cannot come to state the same policy in two ways that do not quite
// agree. An agent in an enrolled tree reads both at once.
func TestBothSectionsStateTheSharedRulesIdentically(t *testing.T) {
	shared, err := credentialRules()
	if err != nil {
		t.Fatal(err)
	}
	// Substantial, or containing it proves nothing: an empty string is in
	// everything.
	if lines := strings.Count(shared, "\n"); lines < 8 {
		t.Fatalf("the shared rules are %d lines, which is too little to be the "+
			"policy both sections rest on:\n%s", lines, shared)
	}
	project, err := CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(project, shared) {
		t.Errorf("the tree's section does not carry the shared rules verbatim:\n%s", project)
	}
	for _, name := range Known() {
		home, err := HomeSection(true)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(home, shared) {
			t.Errorf("%s's home section does not carry the shared rules verbatim:\n%s",
				name, home)
		}
	}
}

// section is the credentials section as instructions() writes it into a tree.
func section(t *testing.T) string {
	t.Helper()
	body, err := CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Writing over a block twice yields the same bytes, so a tree that is already
// current reports no change.
func TestWritingTheSectionIsIdempotent(t *testing.T) {
	body := section(t)
	once := writeInstructions(t, []byte("# My project\n\nSome rules.\n"), body)
	twice := writeInstructions(t, once, body)

	if string(once) != string(twice) {
		t.Errorf("a second write changed the file:\n%s\n---\n%s", once, twice)
	}
	if n := strings.Count(string(twice), SectionBegin); n != 1 {
		t.Errorf("the file carries %d begin markers, want 1:\n%s", n, twice)
	}
}

// A section with no markers around it is wrapped where it stands, whether it
// was written before there were markers or had them stripped by something
// tidying the file. Appending would leave the tree with two of them.
func TestAnUnmarkedSectionIsWrappedInPlace(t *testing.T) {
	body := section(t)
	before := []byte("# My project\n\n" + body + "\n## After\n\nMore notes.\n")

	out := string(writeInstructions(t, before, body))

	heading, _, _ := strings.Cut(body, "\n")
	if n := strings.Count(out, heading); n != 1 {
		t.Errorf("%q appears %d times, want 1:\n%s", heading, n, out)
	}
	if !strings.Contains(out, SectionBegin) || !strings.Contains(out, SectionEnd) {
		t.Errorf("the section was not wrapped:\n%s", out)
	}
	if !strings.Contains(out, "## After\n\nMore notes.\n") {
		t.Errorf("what followed the section was lost:\n%s", out)
	}
}

// Appending keeps what is there and adds the block below it.
func TestTheSectionIsAppendedAndTheFileKept(t *testing.T) {
	body := section(t)
	out := string(writeInstructions(t, []byte("# My project\n\nSome rules.\n"), body))

	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
	if !strings.Contains(out, body) {
		t.Errorf("the section was not added:\n%s", out)
	}
}
