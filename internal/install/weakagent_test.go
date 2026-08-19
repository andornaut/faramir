package install

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// An agent that gets no enforcement gets prose, and prose only works where the
// agent reads it.  Antigravity is the case these cover: its hooks decide and
// cannot rewrite a command, so what an enrolment leaves is the broker's tools
// and the instructions to use them, and every claim below is about those
// instructions arriving.

// Antigravity reads no documented file at the root of a tree, so an enrolment
// writes it one under the directory it does read.  A rules file's activation is
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
	for _, want := range []string{sectionBegin, sectionEnd, "faramir_run"} {
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

// The head is for a file this creates.  An operator who set the activation to
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
// a list of what to fix, and one file listed twice reads as two.  No shipped
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
// named first.  An agent told it is refused everywhere, and finding it is not,
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
		if files[0].accountRules {
			t.Errorf("%s then %s: the shared file claims rules an agent reading it "+
				"does not have", order[0].name, order[1].name)
		}
	}
	// And an agent that does have them is still told so.
	files := homeInstructionFiles([]*agentTarget{guarded})
	if len(files) != 1 || !files[0].accountRules {
		t.Errorf("homeInstructionFiles = %+v, want one file claiming its rules", files)
	}
}

// Enrolling an agent nothing redacts says so.  The tree is shared and the tools
// are registered either way, and an operator reading a clean report would
// otherwise take this tree to be covered the way the others are.
func TestEnrollingAntigravitySaysNothingItRunsIsRedacted(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     keep,
		gid:     keep,
		targets: []*agentTarget{agentTargets["antigravity"]},
	}

	if err := run.agentConfig(); err != nil {
		t.Fatal(err)
	}

	// The route it is told to take, which is all it has.
	body, err := os.ReadFile(filepath.Join(tree, ".agents/mcp_config.json"))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"mcpServers", "faramir", `"mcp"`} {
		if !strings.Contains(string(body), want) {
			t.Errorf("the MCP registration does not carry %q:\n%s", want, body)
		}
	}
	warnings := strings.Join(run.report.Warnings, "\n")
	if !strings.Contains(warnings, "redact") {
		t.Errorf("enrolling an agent nothing redacts warned about nothing:\n%s", warnings)
	}
}

// An agent with no account-wide rules says why it has none.  Two get none and
// not for the same reason, and the difference between them is the difference
// between a project that is covered and one that is not.
func TestEveryAgentWithoutAccountRulesSaysWhy(t *testing.T) {
	seen := 0
	for _, name := range knownAgents() {
		target := agentTargets[name]
		switch {
		case len(target.accountFiles) == 0:
			seen++
			if strings.TrimSpace(target.withoutAccountRules) == "" {
				t.Errorf("%s has no account-wide rules and does not say why, so the "+
					"report has to guess", name)
			}
		case target.withoutAccountRules != "":
			t.Errorf("%s has account-wide rules and also says why it has none", name)
		}
	}
	if seen == 0 {
		t.Error("every agent has account-wide rules, so this asserts nothing")
	}
}

// And `doctor` says that reason rather than pi's.  It is the report an operator
// reads to check coverage, and telling them an extension carries Antigravity's
// rules names a thing that does not exist.
func TestDoctorSaysWhyAntigravityHasNoRules(t *testing.T) {
	var report DoctorReport
	reportAgentRules(&report, t.TempDir(), nil)

	got := finding(t, report, "antigravity")
	if got.Status != StatusNA {
		t.Errorf("status = %q, want %q: %s", got.Status, StatusNA, got.Detail)
	}
	if strings.Contains(got.Detail, "extension") {
		t.Errorf("doctor says an extension carries Antigravity's rules: %s", got.Detail)
	}
	if !strings.Contains(got.Detail, "refuses its file tools") {
		t.Errorf("doctor does not say that nothing refuses it: %s", got.Detail)
	}
	if report.Failed {
		t.Error("an agent that can have no rules failed the report")
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
// the tree is enrolled and not only the once that wrote the files.  Re-running
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

	if !strings.Contains(strings.Join(second.report.Warnings, "\n"), "redacts") {
		t.Errorf("a re-enrolment says nothing about the tree not being redacted: %v",
			second.report.Warnings)
	}
}

// A step that stops partway still says what it wrote.  The tree's own file is
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
// the tree.  Running as root, that is a directory handed to the client group
// somewhere the enrolment was never pointed at.
//
// Both halves of an enrolment create directories, so both are asked.
func TestNoDirectoryIsCreatedThroughALinkOutOfTheTree(t *testing.T) {
	for _, tc := range []struct {
		name, link, made string
		write            func(*project) error
	}{
		{
			name: "the instructions", link: ".agents", made: "rules",
			write: func(p *project) error { return p.instructions() },
		},
		{
			name: "the agent files", link: ".opencode", made: "plugins",
			write: func(p *project) error { return p.agentConfig() },
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
// so what stops this is the refusal rather than the bound.  The mode and owner
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
	if len(target.accountFiles) != 0 {
		t.Error("antigravity writes account-wide rules, and its permission lists " +
			"are the IDE's own state rather than a file an install may write")
	}
}
