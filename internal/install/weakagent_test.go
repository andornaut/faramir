package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// An agent that gets no rule file gets its refusals somewhere else, and where
// that is has to be a file the agent actually reads. The Antigravity IDE is the
// case these cover: its permission lists are its own state, so there is no rule
// file to write, and what holds instead is a hook, account-wide for what it
// reads and per tree for what it runs. Every claim below is about those
// arriving, and about the enrolment saying what is still conditional.

// Antigravity reads no documented file at the root of a tree, so an enrolment
// writes it one under the directory it does read. A rules file's activation is
// frontmatter and always-on is not the default, so a file without the head is
// one the model may never be shown, which for this agent is the whole of what
// it was given.
func TestATreeRulesFileIsHeadedSoTheAgentLoadsIt(t *testing.T) {
	target := agentTargets["antigravity"]
	rules := target.treeInstructions
	if rules.path == "" || rules.head == "" {
		t.Fatal("antigravity names no rules file of its own, so this asserts nothing")
	}
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{target},
	}

	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(tree, rules.path)
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), rules.head) {
		t.Errorf("%s does not start with %q, so the rule is not always on:\n%s",
			rules.path, rules.head, body)
	}
	for _, want := range []string{sectionBegin, sectionEnd, "faramir run"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("%s does not carry %q", rules.path, want)
		}
	}
	// The tree's own file is written as well: it is what every other agent
	// reads, and enrolling one agent must not take it from the rest.
	if !exists(filepath.Join(tree, "AGENTS.md")) {
		t.Error("the tree's own instructions file was not written")
	}

	// And a second enrolment leaves it alone, the markers being what makes the
	// block replaceable rather than repeatable.
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}
	again, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(again) != string(body) {
		t.Errorf("a second enrolment rewrote the file:\n%s\n---\n%s", body, again)
	}
}

// The head is for a file this creates. An operator who set the activation to
// something else keeps it: faramir owns the block between the markers, and the
// file it sits in is theirs, as it is for every other instructions file.
func TestAnExistingRulesFileKeepsItsOwnHead(t *testing.T) {
	target := agentTargets["antigravity"]
	tree := t.TempDir()
	path := filepath.Join(tree, target.treeInstructions.path)
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		t.Fatal(err)
	}
	const theirs = "---\ntrigger: model_decision\ndescription: credentials\n---\n\n# Ours\n"
	if err := os.WriteFile(path, []byte(theirs), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{target},
	}

	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(string(body), theirs) {
		t.Errorf("the file's own frontmatter was rewritten:\n%s", body)
	}
	if !strings.Contains(string(body), sectionBegin) {
		t.Errorf("the section was not added:\n%s", body)
	}
}

// A file two agents read is named once when a run refuses it: an operator gets
// a list of what to fix, and one file listed twice reads as two. No shipped
// pair shares a file, so the targets here are built rather than looked up.
func TestAFileTwoAgentsReadIsNamedOnce(t *testing.T) {
	const shared = "AGENTS.md"
	first := &agentTarget{name: "first", homeInstructions: shared}
	second := &agentTarget{name: "second", homeInstructions: shared}

	paths := homeEditedPaths([]*agentTarget{first, second})

	if n := slices.Index(paths, shared); n < 0 {
		t.Fatalf("paths = %v, want the file they share", paths)
	}
	if n := len(paths); n != 1 {
		t.Errorf("paths = %v, want the shared file named once", paths)
	}
}

// The claim a shared file makes is the weaker of the two, whichever agent was
// named first. An agent told it is refused everywhere, and finding it is not,
// has no reason to believe the next claim; one told to assume nothing stops it
// has been told the truth either way.
func TestTheClaimInASharedHomeFileIsTheWeakerOne(t *testing.T) {
	const path = "AGENTS.md"
	guarded := &agentTarget{
		name:             "guarded",
		homeInstructions: path,
		accountFiles:     []agentFile{{path: ".config/guarded.json"}},
	}
	bare := &agentTarget{name: "bare", homeInstructions: path}

	for _, order := range [][]*agentTarget{{guarded, bare}, {bare, guarded}} {
		files := homeInstructionFiles(order)
		if len(files) != 1 {
			t.Fatalf("%s then %s: %d files, want the one they share",
				order[0].name, order[1].name, len(files))
		}
		if files[0].path != path {
			t.Errorf("%s then %s: the shared file is %q, want %q",
				order[0].name, order[1].name, files[0].path, path)
		}
	}
	// And one agent alone still names it once.
	files := homeInstructionFiles([]*agentTarget{guarded})
	if len(files) != 1 || files[0].path != path {
		t.Errorf("homeInstructionFiles = %+v, want the one file", files)
	}
}

// Enrolling says what is conditional about it. Everything written into the tree
// is inert until Antigravity has opened that tree as a project, and an operator
// reading a clean report would take the tree to be covered from the moment the
// command returned.
func TestEnrollingAntigravitySaysTheTreeIsInertUntilItIsOpened(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{agentTargets["antigravity"]},
	}

	// The prose is the whole of what a tree gets: the hook that routes what it
	// runs is installed for the account, and the deny rules with it.
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}
	if err := run.agentConfig(); err != nil {
		t.Fatal(err)
	}

	// The rules file, which is what this agent reads in a tree.
	body, err := os.ReadFile(filepath.Join(tree, ".agents/rules/faramir.md"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"trigger: always_on", "faramir run"} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the tree's rules file does not carry %q:\n%s", want, body)
		}
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	if !strings.Contains(warnings, "project it has opened") {
		t.Errorf("enrolling said nothing about the tree being inert until the "+
			"agent opens it:\n%s", warnings)
	}
}

// Every agent has something account-wide, which is what makes a tree nobody
// enrolled covered: the deny rules an agent enforces itself, or faramir's own
// guard reached through a hook, a plugin or an extension installed in a home.
//
// This is the invariant the whole arrangement rests on. An agent added without
// one is an agent whose refusals reach only the trees somebody enrolled, and
// nothing else here would say so.
func TestEveryAgentIsCoveredAccountWide(t *testing.T) {
	for _, name := range knownAgents() {
		if len(agentTargets[name].accountFiles) == 0 {
			t.Errorf("%s writes nothing into a home, so a tree nobody enrolled has "+
				"none of its refusals", name)
		}
	}
}

// `doctor` reports Antigravity as an agent with account-wide files rather than
// one with none. It has no rule file and never will, its permission lists being
// its own state, but the hook it reads for every workspace is written into a
// home like any other account file, and the report an operator reads to check
// coverage has to name it.
func TestDoctorReportsAntigravitysAccountWideHook(t *testing.T) {
	if len(agentTargets["antigravity"].accountFiles) == 0 {
		t.Fatal("the IDE has no account-wide files, so nothing refuses its file " +
			"tools outside an enrolled tree")
	}
	// A home the agent is in: an empty one is reported as an agent nobody runs
	// here, which is a different finding and true of every target.
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config/Antigravity"), 0o700); err != nil {
		t.Fatal(err)
	}
	var report DoctorReport
	reportAgentRules(&report, home, nil)

	got := finding(t, report, "antigravity")
	// Absent from a home nothing was installed into, which is a missing file
	// rather than an agent that can have none.
	if got.Status == StatusNA {
		t.Errorf("doctor still reports it as an agent that can have no rules: %s",
			got.Detail)
	}
	if !strings.Contains(got.Detail, "hooks.json") {
		t.Errorf("doctor does not name the file its refusals are written into: %s",
			got.Detail)
	}
	if strings.Contains(got.Detail, "extension") {
		t.Errorf("doctor says an extension carries Antigravity's rules: %s", got.Detail)
	}
}

// Every directory an enrolment creates in a tree is shared, at every level.
// Antigravity's rules file sits under a directory its config file does not, so
// the instructions step is what creates it, and an ancestor left outside the
// share is one a later walk widens, reporting a change on a re-enrolment an
// operator reads as a no-op.
func TestTheDirectoriesTheInstructionsNeedAreSharedAtEveryLevel(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{agentTargets["antigravity"]},
	}

	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	rules := agentTargets["antigravity"].treeInstructions.path
	for dir := filepath.Dir(rules); dir != "."; dir = filepath.Dir(dir) {
		info, err := os.Stat(filepath.Join(tree, dir))
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm() & 0o070; got != 0o070 {
			t.Errorf("%s is %04o: the client group cannot enter it", dir, info.Mode().Perm())
		}
		if info.Mode()&os.ModeSetgid == 0 {
			t.Errorf("%s is %v, want setgid as the share leaves the rest of the tree",
				dir, info.Mode())
		}
	}
}

// The warning is what says this tree is not covered, so it is said every time
// the tree is enrolled and not only the once that wrote the files. Re-running
// an enrolment is the ordinary case, and a silent one reads as a tree covered
// the way the others are.
func TestTheAntigravityWarningIsRepeatedOnEveryEnrolment(t *testing.T) {
	tree := t.TempDir()
	opts := ProjectOptions{Dir: tree, ConfigDir: t.TempDir()}
	first := &project{opts: opts, uid: keep, gid: keep,
		targets: []*agentTarget{agentTargets["antigravity"]}}
	if err := first.agentConfig(); err != nil {
		t.Fatal(err)
	}
	if len(first.report.Warnings) == 0 {
		t.Fatal("the first enrolment warned about nothing")
	}

	// The same tree again, with nothing left to write.
	second := &project{opts: opts, uid: keep, gid: keep,
		targets: []*agentTarget{agentTargets["antigravity"]}}
	if err := second.agentConfig(); err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(strings.Join(second.report.Warnings, "\n"), "project it has opened") {
		t.Errorf("a re-enrolment says nothing about the tree being inert: %v",
			second.report.Warnings)
	}
}

// A step that stops partway still says what it wrote. The tree's own file is
// written before an agent's own one, so a failure on the second leaves a report
// that names neither unless the step is recorded first.
func TestTheInstructionsStepReportsWhatItWroteBeforeFailing(t *testing.T) {
	tree := t.TempDir()
	// A regular file where the rules directory has to go, which the creation
	// cannot make a directory of.
	if err := os.WriteFile(filepath.Join(tree, ".agents"), []byte("not a directory\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{agentTargets["antigravity"]},
	}

	err := run.instructions()

	if err == nil {
		t.Fatal("a run wrote a rules file into a regular file")
	}
	var reported bool
	for _, step := range run.report.Steps {
		if step.Name == "instructions" && strings.Contains(step.Detail, "AGENTS.md") {
			reported = true
		}
	}
	if !reported {
		t.Errorf("the report does not name the file that was written before the "+
			"failure: %+v", run.report.Steps)
	}
}

// A directory a level below a link is the case the file bound cannot answer:
// there is no file yet to resolve, so the creation is what would land outside
// the tree. Running as root, that is a directory handed to the client group
// somewhere the enrolment was never pointed at.
//
// The instructions half is what creates a directory in a tree now: the only
// tree config left is Claude Code's settings, which goes in a directory the
// agent already has rather than one an enrolment makes.
func TestNoDirectoryIsCreatedThroughALinkOutOfTheTree(t *testing.T) {
	for _, tc := range []struct {
		name, link, made string
		write            func(*project) error
	}{
		{
			name: "the instructions", link: ".agents", made: "rules",
			write: func(p *project) error { return p.instructions() },
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tree, outside := t.TempDir(), t.TempDir()
			if err := os.Symlink(outside, filepath.Join(tree, tc.link)); err != nil {
				t.Fatal(err)
			}
			testNoDirectoryThroughALink(t, tree, outside, tc.link, tc.made, tc.write)
		})
	}
}

// A link that stays inside the tree is refused as well, and this is the case
// the pin alone does not cover: a root will follow one that does not escape it,
// so what stops this is the refusal rather than the bound. The mode and owner
// asserted on a link land on whatever it points at, which is the reason
// ensureDir refuses one too.
func TestNoDirectoryIsCreatedThroughALinkInsideTheTree(t *testing.T) {
	tree := t.TempDir()
	target := filepath.Join(tree, "somewhere-else")
	if err := os.Mkdir(target, 0o750); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(tree, ".agents")); err != nil {
		t.Fatal(err)
	}

	testNoDirectoryThroughALink(t, tree, target, ".agents", "rules",
		func(p *project) error { return p.instructions() })
}

// testNoDirectoryThroughALink is the assertion both cases make: preflight
// refuses, the step refuses, and nothing was created where the link points.
func testNoDirectoryThroughALink(t *testing.T, tree, at, link, made string,
	write func(*project) error) {
	t.Helper()
	run := &project{
		opts: ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:  keep,
		gid:  keep,
		targets: []*agentTarget{
			agentTargets["antigravity"], agentTargets["opencode"],
		},
	}

	// Preflight answers first, before the share that cannot be undone, and says
	// which component is a link: the pin's own error names neither.
	if err := run.refuseUnwritableFiles(); err == nil {
		t.Error("preflight passed a link a later step would create through")
	} else {
		for _, want := range []string{filepath.Join(tree, link), "symlink"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("the refusal does not say %q: %v", want, err)
			}
		}
	}
	// And the step itself refuses, rather than relying on being asked.
	if err := write(run); err == nil {
		t.Error("the step created through a link")
	}
	if exists(filepath.Join(at, made)) {
		t.Errorf("%s was created through the link", filepath.Join(at, made))
	}
}

// Nothing is auto-approved on its behalf: there is no allow to return, and a
// report claiming the Bash trade was taken would be naming a cost this agent
// does not pay.
func TestAnAgentWithNoHookTakesNothingAway(t *testing.T) {
	target := agentTargets["antigravity"]
	if target.autoApprovesBash {
		t.Error("antigravity claims to auto-approve Bash, having no hook that could")
	}
	// What it writes account-wide is a hook, not a permission rule: its lists are
	// the IDE's own state, and an install that wrote one would be writing a file
	// the agent does not read.
	for _, file := range target.accountFiles {
		if !strings.HasSuffix(file.path, "hooks.json") {
			t.Errorf("antigravity writes %s account-wide, which is not a file it "+
				"reads: its permission lists are the IDE's own state", file.path)
		}
	}
}
