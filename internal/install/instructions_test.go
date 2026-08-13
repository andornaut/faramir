package install

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// section is the credentials section as instructions() writes it into a tree.
func section(t *testing.T) string {
	t.Helper()
	body, err := credentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// The four placements, and what each one licenses.  The markers are what makes
// a block replaceable: what is between them is faramir's whatever it now says,
// and everything outside them is somebody else's.
func TestWhereTheSectionGoes(t *testing.T) {
	body := section(t)
	wrapped := sectionBlock(body)
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
			sectionBegin + "\n# Credentials\n\nWhatever the last version said.\n" + sectionEnd + "\n",
			placeReplace,
		},
		{"the section with its markers stripped", "# Project\n\n" + body, placeWrap},
		{"the section and nothing else, unmarked", body, placeWrap},
		{
			// The wrap matches the text exactly, so a copy reworded past that is
			// one it cannot delimit.  Appending would leave two sets of
			// credentials instructions contradicting each other.
			"an unmarked section in words that are not these",
			"# Project\n\n# Credentials\n\nRun things with faramir_run, or so we used to.\n",
			placeStale,
		},
		{"a begin with no end", sectionBegin + "\n" + body, placeRefuse},
		{"an end with no begin", body + sectionEnd + "\n", placeRefuse},
		{"the markers inverted", sectionEnd + "\n" + body + sectionBegin + "\n", placeRefuse},
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
	stale := "# Project\n\n" + sectionBegin + "\n# Credentials\n\nOld words.\n" + sectionEnd + "\n"

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

// Writing over a block twice yields the same bytes, so a tree that is already
// current reports no change.
func TestWritingTheSectionIsIdempotent(t *testing.T) {
	body := section(t)
	once := writeInstructions(t, []byte("# My project\n\nSome rules.\n"), body)
	twice := writeInstructions(t, once, body)

	if string(once) != string(twice) {
		t.Errorf("a second write changed the file:\n%s\n---\n%s", once, twice)
	}
	if n := strings.Count(string(twice), sectionBegin); n != 1 {
		t.Errorf("the file carries %d begin markers, want 1:\n%s", n, twice)
	}
}

// A section with no markers around it is wrapped where it stands, whether it
// was written before there were markers or had them stripped by something
// tidying the file.  Appending would leave the tree with two of them.
func TestAnUnmarkedSectionIsWrappedInPlace(t *testing.T) {
	body := section(t)
	before := []byte("# My project\n\n" + body + "\n## After\n\nMore notes.\n")

	out := string(writeInstructions(t, before, body))

	heading := strings.SplitN(body, "\n", 2)[0]
	if n := strings.Count(out, heading); n != 1 {
		t.Errorf("%q appears %d times, want 1:\n%s", heading, n, out)
	}
	if !strings.Contains(out, sectionBegin) || !strings.Contains(out, sectionEnd) {
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

// A file with one marker is left alone: where the block stops cannot be read off
// it, and rewriting past the wrong point takes somebody's prose with it.
func TestAHalfMarkedFileIsRefused(t *testing.T) {
	body := section(t)
	current := []byte("# My project\n\n" + sectionBegin + "\n" + body)

	if place, _, _ := placeSection(current, body); place != placeRefuse {
		t.Fatalf("placeSection = %v, want %v", place, placeRefuse)
	}
}

// The wrap matches on the shipped section's own text, so it holds only while
// that text is what an unmarked file carries.  Anything it cannot match must
// reach placeStale rather than placeAppend: a second credentials section is the
// one outcome worth avoiding, saying something the first one contradicts.
func TestTheShippedSectionIsWhatTheWrapLooksFor(t *testing.T) {
	body := section(t)
	if place, _, _ := placeSection([]byte(body), body); place != placeWrap {
		t.Errorf("the shipped section is not recognised unmarked: placeSection = %v", place)
	}
}

// Changing the shipped snippet must not give an already-enrolled tree a second
// section.  The wording changes; the heading is what an older copy is found by,
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
		"faramir_run.\n"

	place, _, _ := placeSection([]byte(older), body)
	if place != placeStale {
		t.Errorf("placeSection = %v, want %v: an older section would be left in "+
			"place beside a new one", place, placeStale)
	}
}

// Both halves are needed to call a file stale.  A heading of somebody's own is
// not this section, and a file that merely names the tool is the case the
// markers exist to unblock.
func TestAFileIsOnlyStaleWhenItCarriesBothSigns(t *testing.T) {
	body := section(t)
	heading, _, _ := strings.Cut(body, "\n")
	for _, tc := range []struct {
		name    string
		current string
		want    sectionPlacement
	}{
		{"the heading and no mention of the tool", "# Project\n\n" + heading + "\n\nMy own keys.\n", placeAppend},
		{"the tool and no such heading", "# Project\n\nWe run faramir here.\n", placeAppend},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got, _, _ := placeSection([]byte(tc.current), body); got != tc.want {
				t.Errorf("placeSection = %v, want %v", got, tc.want)
			}
		})
	}
}

// A symlinked instructions file is left as it is.  These are the operator's own
// prose, and a dotfiles manager keeps such a file as a link into a repository it
// owns: writing renames a new file over the path, so the link would be gone and
// the repository's copy left unread.
func TestASymlinkedHomeFileIsLeftAlone(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentTargets["claude"].homeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	// The dotfiles repository's copy, and the link an operator keeps in its place.
	target := filepath.Join(home, "dotfiles-CLAUDE.md")
	if err := os.WriteFile(target, []byte("# My rules\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	run := initHome(t, home, "claude")

	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced with a regular file, so the operator's " +
			"dotfiles copy is no longer what the agent reads")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# My rules\n" {
		t.Errorf("the file the link points at was written through:\n%s", body)
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	if !strings.Contains(warnings, path) || !strings.Contains(warnings, "symlink") {
		t.Errorf("the symlink was passed over without saying so: %v", run.report.Warnings)
	}
}

// faramir owns the block between the markers, not the file it sits in, and the
// block is documentation rather than something enforcement rests on.  So an
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
	if _, err := (fsys{}).sectionFile(kept, body, keep, keep); err != nil {
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
	if _, err := (fsys{}).sectionFile(made, body, keep, keep); err != nil {
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

// A dry run is the one form that does not need root, so a file it cannot read
// is reported as no change rather than stopping the run, as ensureDir does for
// a directory it cannot look inside.
func TestADryRunSurvivesAnUnreadableInstructionsFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root, which can read the file this makes unreadable")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	if err := os.WriteFile(path, []byte("# Project\n"), 0o000); err != nil {
		t.Fatal(err)
	}

	changed, err := fsys{dryRun: true}.sectionFile(path, section(t), keep, keep)
	if err != nil {
		t.Fatalf("a dry run stopped on a file it cannot read: %v", err)
	}
	if changed {
		t.Error("a file that could not be read was reported as changed")
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

// What an agent is told about waiting for an approval only holds where one can
// be raised.  On any other host it describes a refusal that never happens, and
// instructions an agent cannot act on are instructions it learns to skim.
func TestTheApprovalParagraphIsWrittenOnlyOnASudoHost(t *testing.T) {
	const marker = "approval_in_progress"
	granted, err := credentialsSection(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(granted, marker) {
		t.Errorf("a host with a sudo grant is not told about %s:\n%s", marker, granted)
	}
	withheld, err := credentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withheld, marker) {
		t.Errorf("a host with no sudo grant is told about %s:\n%s", marker, withheld)
	}
}

// initHome runs `init`'s account-level agent step for real against a home the
// test built, so what is asserted is the bytes that land in it.  Ownership left
// alone: this runs unprivileged, and a chown to root would fail before anything
// was written.
func initHome(t *testing.T, home string, agents ...string) *runner {
	t.Helper()
	run := &runner{
		opts:         Options{Agents: agents},
		layout:       testLayout(),
		operatorUID:  keep,
		operatorGID:  keep,
		operatorHome: home,
	}
	if err := run.stepAgentConfig(); err != nil {
		t.Fatal(err)
	}
	return run
}

// Every agent gets the account-wide section, in the file that agent reads for
// every project.  The deny rules hold wherever it is working, so the paragraph
// explaining them has to as well.
func TestInitWritesTheSectionIntoEveryAgentsHomeFile(t *testing.T) {
	home := t.TempDir()

	initHome(t, home, knownAgents()...)

	for _, name := range knownAgents() {
		target := agentTargets[name]
		if target.homeInstructions == "" {
			t.Errorf("%s names no home instructions file, so it is told nothing", name)
			continue
		}
		body, err := os.ReadFile(filepath.Join(home, target.homeInstructions))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, want := range []string{sectionBegin, sectionEnd, "Never route around a refusal"} {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s: %s does not carry %q", name, target.homeInstructions, want)
			}
		}
	}
}

// The operator's own global instructions are the file this writes into, so what
// it must not do is disturb anything outside the markers.
func TestInitKeepsTheOperatorsOwnProseInTheirHomeFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentTargets["claude"].homeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# My rules\n\nAlways run the tests.\n\n" +
		sectionBegin + "\n# Credentials\n\nWhat an older run wrote.\n" + sectionEnd +
		"\n\n## After\n\nAnd this.\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}

	initHome(t, home, "claude")

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(body)
	for _, want := range []string{"# My rules\n\nAlways run the tests.\n", "## After\n\nAnd this.\n"} {
		if !strings.Contains(got, want) {
			t.Errorf("the operator's own prose was disturbed, %q is gone:\n%s", want, got)
		}
	}
	if strings.Contains(got, "What an older run wrote.") {
		t.Errorf("the stale block survived:\n%s", got)
	}
	if n := strings.Count(got, sectionBegin); n != 1 {
		t.Errorf("the file carries %d begin markers, want 1:\n%s", n, got)
	}
}

// A home file with one marker is left exactly as it is and reported.  The rules
// beside it are written either way, so this is a warning rather than a failure:
// what is missing is the paragraph explaining them, not the refusal itself.
func TestInitLeavesAHalfMarkedHomeFileAlone(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentTargets["claude"].homeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# My rules\n\n" + sectionBegin + "\n# Credentials\n\nHalf a block.\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}

	run := initHome(t, home, "claude")

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != before {
		t.Errorf("the file was rewritten:\n%s", body)
	}
	if len(run.report.Warnings) == 0 {
		t.Fatal("nothing was reported about a file that could not be written")
	}
	if !strings.Contains(strings.Join(run.report.Warnings, "\n"), path) {
		t.Errorf("the warning does not name the file: %v", run.report.Warnings)
	}
	// The rules are the enforcement and must land regardless.
	if !exists(filepath.Join(home, ".claude", "settings.json")) {
		t.Error("the deny rules were not written")
	}
}

// A path outside the home, or one an agent does not read, is a section written
// where nothing loads it.  Checked here because it is not visible at runtime:
// the file is written, and the agent simply never says anything different.
func TestEveryHomeInstructionsPathIsRelativeToTheHome(t *testing.T) {
	for _, name := range knownAgents() {
		path := agentTargets[name].homeInstructions
		if path == "" {
			t.Errorf("%s names no home instructions file", name)
			continue
		}
		if filepath.IsAbs(path) || strings.HasPrefix(path, "..") {
			t.Errorf("%s: %q is not inside the operator's home", name, path)
		}
		if filepath.Ext(path) != ".md" {
			t.Errorf("%s: %q is not markdown, so an agent reading prose will not load it",
				name, path)
		}
	}
}
