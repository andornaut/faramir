package install

import (
	"strings"
	"testing"
)

// section is the credentials section as instructions() writes it.
func section(t *testing.T) string {
	t.Helper()
	snippet, err := readAsset("agent/instructions.md.snippet")
	if err != nil {
		t.Fatal(err)
	}
	return strings.TrimRight(string(snippet), "\n") + "\n"
}

// The three states, and what each one licenses.  No markers anywhere: the
// section's own text is the evidence, and it is evidence nothing can strip
// without changing what the file says.
func TestWhatAFileShowsAboutTheSection(t *testing.T) {
	body := section(t)
	for _, tc := range []struct {
		name    string
		current string
		want    sectionState
	}{
		{"an empty file", "", sectionAbsent},
		{"no sign of faramir", "# Project\n\nSome notes.\n", sectionAbsent},
		{"the section word for word", "# Project\n\n" + body, sectionCurrent},
		{"the section and nothing else", body, sectionCurrent},
		{
			// What an earlier version wrote, or the same section reworded by
			// whatever last tidied the file.  Not ours to rewrite either way.
			"a section that has drifted",
			"# Credentials\n\nRun things with faramir_run, or so we used to.\n",
			sectionDrifted,
		},
		{
			// Over-reported on purpose: a warning costs less than a second set of
			// instructions contradicting the first.
			"prose that merely mentions the tool",
			"# Project\n\nWe use faramir on this host.\n",
			sectionDrifted,
		},
		{
			// The markers an earlier version wrapped the section in are still in
			// some files.  The section between them is word for word what is
			// written now, so those files read as current and are left alone.
			"the section inside markers an earlier version left behind",
			"<!-- BEGIN faramir: credentials -->\n" + body + "<!-- END faramir: credentials -->\n",
			sectionCurrent,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := sectionIn([]byte(tc.current), body); got != tc.want {
				t.Errorf("sectionIn = %v, want %v", got, tc.want)
			}
		})
	}
}

// Appending keeps what is there and adds the section.
func TestTheSectionIsAppendedAndTheFileKept(t *testing.T) {
	out := string(appendSection([]byte("# My project\n\nSome rules.\n"), section(t)))

	if !strings.HasPrefix(out, "# My project\n\nSome rules.\n") {
		t.Errorf("the project's own text was disturbed:\n%s", out)
	}
	if !strings.Contains(out, section(t)) {
		t.Errorf("the section was not added:\n%s", out)
	}
}

// Enrolling twice must not leave the instructions in twice.  With no markers,
// what makes that hold is that the second run finds the section already there
// and writes nothing: appendSection is never reached again.
func TestASecondEnrolmentAddsNothing(t *testing.T) {
	body := section(t)
	once := appendSection([]byte("# My project\n"), body)

	if got := sectionIn(once, body); got != sectionCurrent {
		t.Fatalf("sectionIn after one enrolment = %v, want %v", got, sectionCurrent)
	}
	heading := strings.SplitN(body, "\n", 2)[0]
	if n := strings.Count(string(once), heading); n != 1 {
		t.Errorf("%q appears %d times, want 1:\n%s", heading, n, once)
	}
}

// An empty file gets the section and no leading blank line.
func TestAnEmptyFileGetsTheSectionAlone(t *testing.T) {
	if got := string(appendSection(nil, section(t))); got != section(t) {
		t.Errorf("an empty file got %q", got)
	}
	if got := string(appendSection([]byte("\n\n"), section(t))); got != section(t) {
		t.Errorf("a blank file got %q", got)
	}
}

// The weakest signal has to be able to fire, which it cannot if what is
// shipped never says the word.
func TestTheShippedSectionMentionsTheTool(t *testing.T) {
	if !strings.Contains(strings.ToLower(section(t)), "faramir") {
		t.Error("the section does not mention faramir, so a drifted copy of it " +
			"would never be recognised")
	}
}
