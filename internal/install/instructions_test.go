package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
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
			"# Project\n\n" + heading + "\n\nRun things with faramir_run, or so we used to.\n",
			placeStale,
		},
		// Both signs are needed to call a file stale: a heading of somebody's own
		// is not this section, and merely naming the tool is the case the markers
		// exist to unblock.
		{"the heading with no mention of the tool", "# Project\n\n" + heading + "\n\nMy own keys.\n", placeAppend},
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

// A symlinked instructions file is followed and the section written into what
// it points at.  A dotfiles manager keeps such a file as a link into a
// repository it owns, and writing to the link would leave a regular file where
// the link was and the repository's copy stale and no longer read.
func TestASymlinkedHomeFileIsWrittenThroughToItsTarget(t *testing.T) {
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

	initHome(t, home, "claude")

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
	if !strings.Contains(string(body), sectionBegin) {
		t.Errorf("the file the link points at did not get the section:\n%s", body)
	}
	if !strings.HasPrefix(string(body), "# My rules\n") {
		t.Errorf("the operator's own text was disturbed:\n%s", body)
	}
	// The target keeps its own mode, as any file this did not create does.
	if targetInfo, err := os.Stat(target); err != nil {
		t.Fatal(err)
	} else if targetInfo.Mode().Perm() != 0o600 {
		t.Errorf("the target is %04o, want the 0600 it had", targetInfo.Mode().Perm())
	}
}

// A link is followed only to a regular file the operator owns.  `init` runs as
// root on a path inside a directory the account the agent runs as can write, so
// a link re-pointed at a file root can write would otherwise turn this into an
// append as root.
func TestALinkToAFileTheOperatorDoesNotOwnIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	target := filepath.Join(dir, "somebody-elses.md")
	const before = "# Not yours\n"
	if err := os.WriteFile(target, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	// An operator that is not this file's owner, which is what the check asks.
	_, err := (fsys{}).sectionFile(path, section(t), "", os.Getuid()+1, keep, "")

	if !errors.Is(err, errNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if !outOfDate(err) {
		t.Error("a link this will not follow does not fail the run")
	}
	if body, readErr := os.ReadFile(target); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was written anyway:\n%s", body)
	}
}

// A link naming a path that is not there is refused rather than created
// through: this runs as root, so creating it would put a root-made file
// wherever the link happens to aim.
func TestADanglingLinkIsRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "AGENTS.md")
	target := filepath.Join(dir, "nothing-here.md")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	_, err := (fsys{}).sectionFile(path, section(t), "", keep, keep, "")

	if !errors.Is(err, errNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if exists(target) {
		t.Error("the dangling link was created through")
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
	if _, err := (fsys{}).sectionFile(kept, body, "", keep, keep, ""); err != nil {
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
	if _, err := (fsys{}).sectionFile(made, body, "", keep, keep, ""); err != nil {
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

	changed, err := fsys{dryRun: true}.sectionFile(path, section(t), "", keep, keep, "")
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

// What an agent is told about waiting for an escalation only holds where one can
// be raised.  On any other host it describes a refusal that never happens, and
// instructions an agent cannot act on are instructions it learns to skim.
func TestTheEscalationParagraphIsWrittenOnlyOnASudoHost(t *testing.T) {
	const marker = "escalation_in_progress"
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
	run, err := initHomeErr(t, home, agents...)
	if err != nil {
		t.Fatal(err)
	}
	return run
}

// initHomeErr is initHome for a test about the run failing.
func initHomeErr(t *testing.T, home string, agents ...string) (*runner, error) {
	t.Helper()
	run := &runner{
		opts:         Options{Agents: agents},
		layout:       testLayout(),
		operatorUID:  keep,
		operatorGID:  keep,
		operatorHome: home,
	}
	if err := run.refuseUnwritableAgentFiles(); err != nil {
		return run, err
	}
	return run, run.stepAgentConfig()
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

// A home file this cannot bring up to date fails the run: these files carry the
// policy an agent is held to, so reporting success would leave an operator
// believing a host says something it does not.  The file is left exactly as it
// is, where the block stops not being readable off it.
func TestInitFailsOnAHomeFileItCannotBringUpToDate(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentTargets["claude"].homeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# My rules\n\n" + sectionBegin + "\n# Credentials\n\nHalf a block.\n"
	if err := os.WriteFile(path, []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}

	run, err := initHomeErr(t, home, "claude", "opencode")

	if err == nil {
		t.Fatal("a run that could not update the instructions reported success")
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
	// It says what to do, not only what happened.
	if !strings.Contains(err.Error(), "faramir init") {
		t.Errorf("the error does not name the command to run again: %v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was rewritten:\n%s", body)
	}
	// The rules are the enforcement and land regardless of the prose.
	if !exists(filepath.Join(home, ".claude", "settings.json")) {
		t.Error("the deny rules were not written")
	}
	// And the run does not stop at the first one: every other agent's section is
	// brought up to date, and the failure names them all at the end.
	other := filepath.Join(home, agentTargets["opencode"].homeInstructions)
	if !exists(other) {
		t.Error("opencode's section was skipped because claude's file was broken")
	}
	// What was written is still reported, so a failure is not a blank report.
	var named bool
	for _, step := range run.report.Steps {
		if step.Name == "agent instructions" && strings.Contains(step.Detail, other) {
			named = true
		}
	}
	if !named {
		t.Errorf("the report does not say what was written: %+v", run.report.Steps)
	}
}

// The same for an enrolment, whose section is the one that travels in the
// project's own repository.
func TestInitProjectFailsOnAnInstructionsFileItCannotBringUpToDate(t *testing.T) {
	tree := t.TempDir()
	path := filepath.Join(tree, "AGENTS.md")
	before := "# Project\n\n" + sectionEnd + "\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{opts: ProjectOptions{Dir: tree}, uid: keep, gid: keep}

	err := run.instructions()

	if err == nil {
		t.Fatal("an enrolment that could not update the instructions reported success")
	}
	if !strings.Contains(err.Error(), "init-project") {
		t.Errorf("the error does not name the command to run again: %v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was rewritten:\n%s", body)
	}
}

// A path outside the home, or one an agent does not read, is a section written
// where nothing loads it.  Checked here because it is not visible at runtime:
// the file is written, and the agent never says anything different.
func TestEveryHomeInstructionsPathIsRelativeToTheHome(t *testing.T) {
	for _, name := range knownAgents() {
		path := agentTargets[name].homeInstructions
		if path == "" {
			t.Errorf("%s names no home instructions file", name)
			continue
		}
		if filepath.IsAbs(path) || strings.HasPrefix(path, "..") {
			t.Errorf("%s: %q is not inside the agent account's home", name, path)
		}
		if filepath.Ext(path) != ".md" {
			t.Errorf("%s: %q is not markdown, so an agent reading prose will not load it",
				name, path)
		}
	}
}

// What the home section claims about the deny rules has to be true of the agent
// it is written for: pi's are compiled into the extension an enrolment
// installs, and Antigravity has nothing that refuses a file tool anything.  An
// agent told it is refused everywhere, and finding it is not, has no reason to
// believe the next claim.
func TestTheHomeSectionClaimsOnlyWhatTheAgentHas(t *testing.T) {
	const everywhere = "wherever you are working"
	seen := map[bool]int{}
	for _, name := range knownAgents() {
		target := agentTargets[name]
		body, err := homeSection(len(target.accountFiles) > 0)
		if err != nil {
			t.Fatal(err)
		}
		// Whitespace-normalised, the prose being wrapped: a phrase that spans a
		// line break is still the phrase, and rewrapping must not fail this.
		flat := strings.Join(strings.Fields(body), " ")
		hasRules := len(target.accountFiles) > 0
		seen[hasRules]++
		switch claims := strings.Contains(flat, everywhere); {
		case hasRules && !claims:
			t.Errorf("%s has account-wide rules and its section does not say so", name)
		case !hasRules && claims:
			t.Errorf("%s has no account-wide rules and its section says its file "+
				"tools are refused %q", name, everywhere)
		}
		// Either way the policy stands: the rules are the enforcement and this is
		// what the agent is told, and pi is told it in a tree faramir has never
		// enrolled as much as the rest are.
		if !strings.Contains(flat, "Never route around a refusal") {
			t.Errorf("%s is not told the rule that survives having no enforcement", name)
		}
	}
	// Both branches have to be exercised, or this asserts one shape twice.
	if seen[true] == 0 || seen[false] == 0 {
		t.Errorf("agents with rules: %d, without: %d; want both", seen[true], seen[false])
	}
}

// The rules both sections state are one asset rendered into each, so a home and
// a tree cannot come to state the same policy in two ways that do not quite
// agree.  An agent in an enrolled tree reads both at once.
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
	project, err := credentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(project, shared) {
		t.Errorf("the tree's section does not carry the shared rules verbatim:\n%s", project)
	}
	for _, name := range knownAgents() {
		home, err := homeSection(len(agentTargets[name].accountFiles) > 0)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(home, shared) {
			t.Errorf("%s's home section does not carry the shared rules verbatim:\n%s",
				name, home)
		}
	}
}

// Each section still says what only it can, so neither is a copy of the other
// and neither depends on the other being there.
func TestEachSectionSaysWhatOnlyItCan(t *testing.T) {
	project, err := credentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"faramir_run", "faramir_refs",
		"Never write a value down", "Never send one anywhere",
		"not the security\nboundary"} {
		if !strings.Contains(project, want) {
			t.Errorf("the tree's section does not say %q", want)
		}
	}
	home, err := homeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	// What a home is for: there is a route in an enrolled tree and none outside
	// one, which is the question an agent has where no broker is registered.
	for _, want := range []string{"init-project", "ask the operator"} {
		if !strings.Contains(home, want) {
			t.Errorf("the home section does not say %q", want)
		}
	}
	// And not the tree's half: naming a tool an agent has no registration for
	// would be telling it to call something that is not there.
	if strings.Contains(home, "faramir_run") {
		t.Error("the home section names faramir_run, which an agent outside an " +
			"enrolled tree has no registration for")
	}
}

// An agent's settings are a file faramir edits rather than owns, and both
// commands run as root on a path the account the agent runs as can write.  One
// that is not the operator's fails the run: editing it would be root writing a
// file it was never asked to, and chowning it to make that true would take it
// from whoever has it.
func TestAgentSettingsNotOwnedByTheOperatorFailTheRun(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	const before = "{}\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	// An operator that is not this file's owner, which is what the check asks.
	_, _, err := writeAgentFiles(
		fsys{}, home, os.Getuid()+1, keep, 0o700, false, render, files)

	if !errors.Is(err, errNotOperators) {
		t.Fatalf("err = %v, want the file refused", err)
	}
	if !strings.Contains(err.Error(), path) {
		t.Errorf("the error does not name the file: %v", err)
	}
	if body, readErr := os.ReadFile(path); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != before {
		t.Errorf("the file was written anyway:\n%s", body)
	}
}

// A symlinked one is followed to what it points at, as the credentials section
// is: a dotfiles manager keeps such a file as a link, and mergeFile reads
// through a link before renaming a new file over it.
func TestSymlinkedAgentSettingsAreWrittenThroughToTheirTarget(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, ".claude", "settings.json")
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(home, "dotfiles-settings.json")
	if err := os.WriteFile(target, []byte(`{"model":"mine"}`+"\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	if _, _, err := writeAgentFiles(
		fsys{}, home, os.Getuid(), keep, 0o700, false, render, files); err != nil {
		t.Fatal(err)
	}

	if info, err := os.Lstat(path); err != nil {
		t.Fatal(err)
	} else if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the symlink was replaced with a regular file")
	}
	body, err := os.ReadFile(target)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"a": 1`) {
		t.Errorf("the target did not get faramir's keys:\n%s", body)
	}
	if !strings.Contains(string(body), `"model": "mine"`) {
		t.Errorf("the operator's own keys were lost:\n%s", body)
	}
}

// The group is asserted where it is load-bearing and left alone where it is
// not.  A tree's files have to be readable by the client group; in a home the
// group decides nothing, and asserting it would be one more thing a run changes
// without being asked to.
func TestTheGroupIsAssertedOnlyWhereItIsLoadBearing(t *testing.T) {
	groups, err := os.Getgroups()
	if err != nil || len(groups) < 2 {
		t.Skip("this account has no second group to tell the two apart")
	}
	other := -1
	for _, candidate := range groups {
		if candidate != os.Getgid() {
			other = candidate
			break
		}
	}
	if other < 0 {
		t.Skip("this account has no second group to tell the two apart")
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: "settings.json", mode: 0o640, merge: true}}

	for _, tc := range []struct {
		name         string
		groupMatters bool
		want         int
	}{
		{"a home leaves the group alone", false, other},
		{"a tree asserts it", true, os.Getgid()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, "settings.json")
			if err := os.WriteFile(path, []byte("{}\n"), 0o640); err != nil {
				t.Fatal(err)
			}
			if err := os.Chown(path, -1, other); err != nil {
				t.Skipf("cannot move the file into %d: %v", other, err)
			}

			if _, _, err := writeAgentFiles(fsys{}, root, os.Getuid(), os.Getgid(),
				0o700, tc.groupMatters, render, files); err != nil {
				t.Fatal(err)
			}

			info, err := os.Stat(path)
			if err != nil {
				t.Fatal(err)
			}
			stat, ok := info.Sys().(*syscall.Stat_t)
			if !ok {
				t.Fatalf("FileInfo.Sys() = %T, want a *syscall.Stat_t", info.Sys())
			}
			if got := int(stat.Gid); got != tc.want {
				t.Errorf("gid = %d, want %d", got, tc.want)
			}
		})
	}
}

// One agent's rule file that cannot be written must not cost the others theirs,
// nor cost every agent its credentials section.  The run still fails; what it
// must not do is fail early enough to hide what did land.
func TestInitWritesEveryOtherAgentBeforeFailingOnOne(t *testing.T) {
	home := t.TempDir()
	// A link naming a path that is not there, which editedFile refuses for the
	// same reason it refuses somebody else's file: writing it would put a
	// root-made file wherever the link happens to aim.
	blocked := filepath.Join(home, ".config", "opencode", "opencode.json")
	if err := os.MkdirAll(filepath.Dir(blocked), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(home, "nothing-here.json"), blocked); err != nil {
		t.Fatal(err)
	}
	run := &runner{
		opts:         Options{Agents: []string{"claude", "opencode"}},
		layout:       testLayout(),
		operatorUID:  keep,
		operatorGID:  keep,
		operatorHome: home,
	}

	if err := run.refuseUnwritableAgentFiles(); err == nil {
		t.Fatal("preconditions passed a rule file the step then refused")
	}
	// Asked again at the step, which is where the collecting is: preconditions
	// stop a run before anything is written, and this asserts what the step does
	// when it is reached anyway.
	run.agentTargets, _ = resolveAgents(run.opts.Agents, scopeHome, run.operatorHome)
	err := run.stepAgentConfig()

	if err == nil {
		t.Fatal("a run that refused a rule file reported success")
	}
	if !strings.Contains(err.Error(), blocked) {
		t.Errorf("the error does not name the file: %v", err)
	}
	// Claude's rules landed, and the step says so.
	if !exists(filepath.Join(home, ".claude", "settings.json")) {
		t.Error("claude's rules were skipped because opencode's file was refused")
	}
	var reported bool
	for _, step := range run.report.Steps {
		if step.Name == "agent config" && strings.Contains(step.Detail, ".claude/settings.json") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the report never says what was written: %+v", run.report.Steps)
	}
	// And every agent still got its credentials section, opencode's rule file
	// being a separate question from opencode's prose.
	for _, name := range []string{"claude", "opencode"} {
		path := filepath.Join(home, agentTargets[name].homeInstructions)
		if !exists(path) {
			t.Errorf("%s got no credentials section", name)
		}
	}
}

// Two agents whose files are one file are refused, and named as a pair.  A link
// is the ordinary way to get one, an operator keeping a single global
// instructions file for every agent; written, the second section would replace
// the first and the run would report success.
func TestInitRefusesTwoAgentFilesThatAreOneFile(t *testing.T) {
	home := t.TempDir()
	claude := filepath.Join(home, ".claude", "CLAUDE.md")
	gemini := filepath.Join(home, ".gemini", "GEMINI.md")
	for _, dir := range []string{filepath.Dir(claude), filepath.Dir(gemini)} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	const own = "# mine\n"
	if err := os.WriteFile(claude, []byte(own), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(claude, gemini); err != nil {
		t.Fatal(err)
	}

	_, err := initHomeErr(t, home, "antigravity", "claude")

	if err == nil {
		t.Fatal("a run wrote two agents' sections into one file and reported success")
	}
	for _, path := range []string{claude, gemini} {
		if !strings.Contains(err.Error(), path) {
			t.Errorf("the error does not name %s, so the pair cannot be found: %v", path, err)
		}
	}
	// The pair, not one half of it being unwritable for some other reason.
	if !strings.Contains(err.Error(), "are one file") {
		t.Errorf("the error does not say the two are one file: %v", err)
	}
	// Refused before anything was written, which is what makes it recoverable.
	body, readErr := os.ReadFile(claude)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != own {
		t.Errorf("the file was written before the pair was refused:\n%s", body)
	}
}

// The same path twice is one file written once, which is what two agents
// reading one file of their own is.  Only two different paths landing on one
// are two writes with one survivor, so a repeat must not be refused with them.
func TestRefusingOneFileTwiceAllowsTheSamePathTwice(t *testing.T) {
	home := t.TempDir()
	const rel = ".claude/CLAUDE.md"
	if err := os.MkdirAll(filepath.Join(home, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, rel), []byte("# mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	refused := refuseUnwritable(fsys{}, home, os.Getuid(), "", []string{rel, rel})

	if len(refused) > 0 {
		t.Errorf("one path named twice was refused as two files: %v", refused)
	}
}

// A link out of an enrolled tree is refused: following it would apply the
// tree's group and mode to a file the enrolment was never pointed at, so a
// dotfiles copy would come out readable by the account brokered commands run
// as.  In a home there is no such bound, a dotfiles repository being wherever
// the operator keeps it.
func TestALinkOutOfAnEnrolledTreeIsRefused(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "settings.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	for _, tc := range []struct {
		name   string
		inTree bool
		refuse bool
	}{
		{"a tree refuses it", true, true},
		{"a home follows it", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root := t.TempDir()
			path := filepath.Join(root, ".claude", "settings.json")
			if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(target, path); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
				t.Fatal(err)
			}

			_, _, err := writeAgentFiles(fsys{}, root, os.Getuid(), os.Getgid(),
				0o700, tc.inTree, render, files)

			if tc.refuse {
				if !errors.Is(err, errNotOperators) {
					t.Fatalf("err = %v, want the link out of the tree refused", err)
				}
				info, statErr := os.Stat(target)
				if statErr != nil {
					t.Fatal(statErr)
				}
				if info.Mode().Perm() != 0o600 {
					t.Errorf("the file outside the tree is %04o: the tree's mode "+
						"reached it", info.Mode().Perm())
				}
				return
			}
			if err != nil {
				t.Fatalf("a home refused a link to the operator's own file: %v", err)
			}
		})
	}
}

// A plain file is pinned the same way a followed link is.  The check and the
// write are two operations, and a path checked and then written by path is
// resolved twice: the directories these sit in are the operator's, and in an
// enrolled tree the client group's, so either can replace one in between.
func TestAPlainEditedFileIsPinnedToo(t *testing.T) {
	home := t.TempDir()
	realDir := filepath.Join(home, "agent")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(realDir, "settings.json")
	if err := os.WriteFile(path, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	spot, err := (fsys{}).editedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.close()
	if spot.root == nil {
		t.Fatal("a plain file left no pinned directory, so the write resolves the " +
			"path a second time")
	}

	decoy := filepath.Join(home, "decoy")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, realDir); err != nil {
		t.Fatal(err)
	}

	if _, err := (fsys{}).writeEdited(spot, []byte(`{"a":1}`+"\n"), 0o600, keep, keep); err != nil {
		t.Fatal(err)
	}

	if exists(filepath.Join(decoy, "settings.json")) {
		t.Error("the write followed the swapped directory")
	}
	body, err := os.ReadFile(filepath.Join(home, "moved", "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != `{"a":1}`+"\n" {
		t.Errorf("the write did not land in the directory that was checked:\n%s", body)
	}
}

// A followed link is written through a descriptor opened on the target's
// directory, so the path is resolved once.  What that buys, asserted the only
// way it can be from here: the directory the write goes into is the one that
// was checked, so replacing it afterwards reaches nothing this run does.
func TestAFollowedLinkIsWrittenThroughAPinnedDirectory(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "AGENTS.md")
	realDir := filepath.Join(home, "dotfiles")
	if err := os.MkdirAll(realDir, 0o700); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(realDir, "AGENTS.md")
	if err := os.WriteFile(target, []byte("# Mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}

	spot, err := (fsys{}).editedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.close()
	if spot.root == nil {
		t.Fatal("a followed link left no pinned directory, so the write resolves " +
			"the path a second time")
	}

	// The directory is swapped after the check, as an agent owning it could.
	// The descriptor still names the old one, so that is where the write lands.
	decoy := filepath.Join(home, "decoy")
	if err := os.MkdirAll(decoy, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(realDir, filepath.Join(home, "moved")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(decoy, realDir); err != nil {
		t.Fatal(err)
	}

	if _, err := (fsys{}).writeEdited(spot, []byte("# Written\n"), 0o600, keep, keep); err != nil {
		t.Fatal(err)
	}

	if exists(filepath.Join(decoy, "AGENTS.md")) {
		t.Error("the write followed the swapped directory")
	}
	body, err := os.ReadFile(filepath.Join(home, "moved", "AGENTS.md"))
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "# Written\n" {
		t.Errorf("the write did not land in the directory that was checked:\n%s", body)
	}
}

// And it keeps the temp-and-rename, so a run that dies partway leaves the file
// it found rather than half of a new one.
func TestAFollowedLinkKeepsTheTempAndRename(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, "AGENTS.md")
	target := filepath.Join(home, "real.md")
	if err := os.WriteFile(target, []byte("# Mine\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	spot, err := (fsys{}).editedFile(path, os.Getuid(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer spot.close()

	// A temp already sitting there is an error rather than something to
	// truncate: it is not this run's file, and the target is untouched.
	planted := target + ".faramir-tmp"
	if err := os.WriteFile(planted, []byte("theirs\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := (fsys{}).writeEdited(spot, []byte("# Written\n"), 0o600, keep, keep); err == nil {
		t.Error("a planted temp file was written over")
	}
	if body, readErr := os.ReadFile(target); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != "# Mine\n" {
		t.Errorf("the target was changed by a write that failed:\n%s", body)
	}
}

// The bound is on the directory, not the file: Lstat declines to follow only
// the last component, so a symlinked parent would carry the write out of the
// tree before the leaf is looked at.  Refused at the directory, which is the
// level a run reaches first.
func TestASymlinkedParentCannotCarryTheWriteOutOfTheTree(t *testing.T) {
	outside := t.TempDir()
	const before = "{}\n"
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	tree := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, ".claude")); err != nil {
		t.Fatal(err)
	}

	_, _, err := writeAgentFiles(fsys{}, tree, os.Getuid(), os.Getgid(),
		0o2770|os.ModeSetgid, true, render, files)

	if err == nil {
		t.Fatal("a write through a symlinked parent was accepted")
	}
	if !strings.Contains(err.Error(), filepath.Join(tree, ".claude")) {
		t.Errorf("the error does not name the link: %v", err)
	}
	info, statErr := os.Stat(filepath.Join(outside, "settings.json"))
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode().Perm() != 0o600 {
		t.Errorf("the file outside the tree is %04o, want the 0600 it had: the "+
			"tree's mode reached it", info.Mode().Perm())
	}
}

// Creation is bounded the same way: a file this run makes lands in that
// directory as surely as one it edits.
func TestASymlinkedParentCannotCarryACreationOutOfTheTree(t *testing.T) {
	outside := t.TempDir()
	tree := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, ".claude")); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	_, _, err := writeAgentFiles(fsys{}, tree, os.Getuid(), os.Getgid(),
		0o2770|os.ModeSetgid, true, render, files)

	if err == nil {
		t.Fatal("a creation through a symlinked parent was accepted")
	}
	if exists(filepath.Join(outside, "settings.json")) {
		t.Error("a file was created outside the tree being enrolled")
	}
}

// A home has no such bound, a dotfiles repository being wherever the operator
// keeps it, and that is what makes the case above a bound rather than a ban.
func TestASymlinkedParentIsFollowedInAHome(t *testing.T) {
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	render := func(agentFile) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentFile{{path: ".claude/settings.json", mode: 0o640, merge: true}}

	if _, _, err := writeAgentFiles(fsys{}, home, os.Getuid(), os.Getgid(),
		0o700, false, render, files); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(filepath.Join(outside, "settings.json"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"a": 1`) {
		t.Errorf("the dotfiles copy did not get faramir's keys:\n%s", body)
	}
}
