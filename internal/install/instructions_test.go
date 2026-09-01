package install

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// A symlinked instructions file is followed and the section written into what
// it points at. A dotfiles manager keeps such a file as a link into a
// repository it owns, and writing to the link would leave a regular file where
// the link was and the repository's copy stale and no longer read.
func TestASymlinkedHomeFileIsWrittenThroughToItsTarget(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentcfg.Targets["claude"].HomeInstructions)
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
	if !strings.Contains(string(body), agentcfg.SectionBegin) {
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

// A link is followed only to a regular file the operator owns. `init` runs as
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
	_, err := agentcfg.SectionFile(hostfs.FS{}, path, section(t), "", os.Getuid()+1, hostfs.Keep, "")

	if !errors.Is(err, hostfs.ErrNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if !agentcfg.OutOfDate(err) {
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

	_, err := agentcfg.SectionFile(hostfs.FS{}, path, section(t), "", hostfs.Keep, hostfs.Keep, "")

	if !errors.Is(err, hostfs.ErrNotOperators) {
		t.Fatalf("err = %v, want the link refused", err)
	}
	if hostfs.Exists(target) {
		t.Error("the dangling link was created through")
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

	changed, err := agentcfg.SectionFile(hostfs.FS{DryRun: true}, path, section(t), "", hostfs.Keep, hostfs.Keep, "")
	if err != nil {
		t.Fatalf("a dry run stopped on a file it cannot read: %v", err)
	}
	if changed {
		t.Error("a file that could not be read was reported as changed")
	}
}

// What an agent is told about waiting for an escalation only holds where one can
// be raised. On any other host it describes a refusal that never happens, and
// instructions an agent cannot act on are instructions it learns to skim.
func TestTheEscalationParagraphIsWrittenOnlyOnASudoHost(t *testing.T) {
	const marker = "escalation_in_progress"
	granted, err := agentcfg.CredentialsSection(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(granted, marker) {
		t.Errorf("a host with a sudo grant is not told about %s:\n%s", marker, granted)
	}
	withheld, err := agentcfg.CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withheld, marker) {
		t.Errorf("a host with no sudo grant is told about %s:\n%s", marker, withheld)
	}
	// The home says how to raise one, which holds for the same hosts and no
	// others: the grant is the host's rather than any tree's.
	const homeMarker = "Never background it"
	grantedHome, err := agentcfg.HomeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(grantedHome, homeMarker) {
		t.Errorf("a home on a host with a sudo grant is not told %q:\n%s",
			homeMarker, grantedHome)
	}
	withheldHome, err := agentcfg.HomeSection(false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(withheldHome, homeMarker) {
		t.Errorf("a home on a host with no sudo grant is told %q:\n%s",
			homeMarker, withheldHome)
	}
}

// initHome runs `init`'s account-level agent step for real against a home the
// test built, so what is asserted is the bytes that land in it. Ownership left
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
		operatorUID:  hostfs.Keep,
		operatorGID:  hostfs.Keep,
		operatorHome: home,
	}
	if err := run.refuseUnwritableAgentFiles(); err != nil {
		return run, err
	}
	return run, run.stepAgentConfig()
}

// Every agent gets the account-wide section, in the file that agent reads for
// every project. The deny rules hold wherever it is working, so the paragraph
// explaining them has to as well.
func TestInitWritesTheSectionIntoEveryAgentsHomeFile(t *testing.T) {
	home := t.TempDir()

	initHome(t, home, agentcfg.Known()...)

	for _, name := range agentcfg.Known() {
		target := agentcfg.Targets[name]
		if target.HomeInstructions == "" {
			t.Errorf("%s names no home instructions file, so it is told nothing", name)
			continue
		}
		body, err := os.ReadFile(filepath.Join(home, target.HomeInstructions))
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, want := range []string{agentcfg.SectionBegin, agentcfg.SectionEnd, "Never route around a refusal"} {
			if !strings.Contains(string(body), want) {
				t.Errorf("%s: %s does not carry %q", name, target.HomeInstructions, want)
			}
		}
	}
}

// The operator's own global instructions are the file this writes into, so what
// it must not do is disturb anything outside the markers.
func TestInitKeepsTheOperatorsOwnProseInTheirHomeFile(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentcfg.Targets["claude"].HomeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# My rules\n\nAlways run the tests.\n\n" +
		agentcfg.SectionBegin + "\n# Credentials\n\nWhat an older run wrote.\n" + agentcfg.SectionEnd +
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
	if n := strings.Count(got, agentcfg.SectionBegin); n != 1 {
		t.Errorf("the file carries %d begin markers, want 1:\n%s", n, got)
	}
}

// A home file this cannot bring up to date fails the run: these files carry the
// policy an agent is held to, so reporting success would leave an operator
// believing a host says something it does not. The file is left exactly as it
// is, where the block stops not being readable off it.
func TestInitFailsOnAHomeFileItCannotBringUpToDate(t *testing.T) {
	home := t.TempDir()
	path := filepath.Join(home, agentcfg.Targets["claude"].HomeInstructions)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		t.Fatal(err)
	}
	before := "# My rules\n\n" + agentcfg.SectionBegin + "\n# Credentials\n\nHalf a block.\n"
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
	if !hostfs.Exists(filepath.Join(home, ".claude", "settings.json")) {
		t.Error("the deny rules were not written")
	}
	// And the run does not stop at the first one: every other agent's section is
	// brought up to date, and the failure names them all at the end.
	other := filepath.Join(home, agentcfg.Targets["opencode"].HomeInstructions)
	if !hostfs.Exists(other) {
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
	before := "# Project\n\n" + agentcfg.SectionEnd + "\n"
	if err := os.WriteFile(path, []byte(before), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{opts: ProjectOptions{Dir: tree}, uid: hostfs.Keep, gid: hostfs.Keep}

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
// where nothing loads it. Checked here because it is not visible at runtime:
// the file is written, and the agent never says anything different.
func TestEveryHomeInstructionsPathIsRelativeToTheHome(t *testing.T) {
	for _, name := range agentcfg.Known() {
		path := agentcfg.Targets[name].HomeInstructions
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
// installs, and Antigravity has nothing that refuses a file tool anything. An
// agent told it is refused everywhere, and finding it is not, has no reason to
// believe the next claim.
func TestTheHomeSectionClaimsOnlyWhatTheAgentHas(t *testing.T) {
	const everywhere = "wherever you are working"
	seen := map[bool]int{}
	for _, name := range agentcfg.Known() {
		target := agentcfg.Targets[name]
		body, err := agentcfg.HomeSection(true)
		if err != nil {
			t.Fatal(err)
		}
		// Whitespace-normalised, the prose being wrapped: a phrase that spans a
		// line break is still the phrase, and rewrapping must not fail this.
		flat := strings.Join(strings.Fields(body), " ")
		hasRules := len(target.AccountFiles) > 0
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
	// One shape now: every agent has something account-wide, so the section makes
	// the same claim for all of them. A second shape reappearing means an agent
	// was added without account-wide cover, which is what the section would then
	// have to hedge about.
	if seen[false] != 0 {
		t.Errorf("%d agent(s) have nothing account-wide, so the section cannot "+
			"claim what it claims", seen[false])
	}
}

// Each section still says what only it can, so neither is a copy of the other
// and neither depends on the other being there.
func TestEachSectionSaysWhatOnlyItCan(t *testing.T) {
	project, err := agentcfg.CredentialsSection(false)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"faramir run", "faramir refs",
		"Never write a value down", "Never send one anywhere",
		"not the security\nboundary"} {
		if !strings.Contains(project, want) {
			t.Errorf("the tree's section does not say %q", want)
		}
	}
	home, err := agentcfg.HomeSection(true)
	if err != nil {
		t.Fatal(err)
	}
	// What a home is for. The route is named here as well as in a tree, the
	// binary reaching the broker from anywhere on the host, and saying so is the
	// point: an agent working where no enrolment ran would otherwise be refused
	// with nothing to do instead. Escalation is the home's too, the grant being
	// the host's rather than any tree's, and an agent that backgrounds the
	// command loses the approval.
	for _, want := range []string{"faramir run", "faramir refs",
		"faramir run -C", "Never background it"} {
		if !strings.Contains(home, want) {
			t.Errorf("the home section does not say %q", want)
		}
	}
	// And it does not send the agent to the operator for a value it can fetch
	// itself, which is what it had to do when the route was registered per tree.
	if strings.Contains(home, "Outside one there is no such route") {
		t.Error("the home section still says there is no route outside an enrolled " +
			"tree, which the binary makes untrue")
	}
}

// An agent's settings are a file faramir edits rather than owns, and both
// commands run as root on a path the account the agent runs as can write. One
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
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	// An operator that is not this file's owner, which is what the check asks.
	_, _, err := agentcfg.WriteFiles(
		hostfs.FS{}, nil, home, "", os.Getuid()+1, hostfs.Keep, 0o700, false, render, files)

	if !errors.Is(err, hostfs.ErrNotOperators) {
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
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	if _, _, err := agentcfg.WriteFiles(
		hostfs.FS{}, nil, home, "", os.Getuid(), hostfs.Keep, 0o700, false, render, files); err != nil {
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
// not. A tree's files have to be readable by the client group; in a home the
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
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: "settings.json", Mode: 0o640, Merge: true}}

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

			if _, _, err := agentcfg.WriteFiles(hostfs.FS{}, nil, root, "", os.Getuid(), os.Getgid(),
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
// nor cost every agent its credentials section. The run still fails; what it
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
		operatorUID:  hostfs.Keep,
		operatorGID:  hostfs.Keep,
		operatorHome: home,
	}

	if err := run.refuseUnwritableAgentFiles(); err == nil {
		t.Fatal("preconditions passed a rule file the step then refused")
	}
	// Asked again at the step, which is where the collecting is: preconditions
	// stop a run before anything is written, and this asserts what the step does
	// when it is reached anyway.
	run.agentTargets, _ = agentcfg.Resolve(run.opts.Agents, agentcfg.ScopeHome, run.operatorHome, "")
	err := run.stepAgentConfig()

	if err == nil {
		t.Fatal("a run that refused a rule file reported success")
	}
	if !strings.Contains(err.Error(), blocked) {
		t.Errorf("the error does not name the file: %v", err)
	}
	// Claude's rules landed, and the step says so.
	if !hostfs.Exists(filepath.Join(home, ".claude", "settings.json")) {
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
		path := filepath.Join(home, agentcfg.Targets[name].HomeInstructions)
		if !hostfs.Exists(path) {
			t.Errorf("%s got no credentials section", name)
		}
	}
}

// Two agents whose files are one file are refused, and named as a pair. A link
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
	// Blocked before anything was written, which is what makes it recoverable.
	body, readErr := os.ReadFile(claude)
	if readErr != nil {
		t.Fatal(readErr)
	}
	if string(body) != own {
		t.Errorf("the file was written before the pair was refused:\n%s", body)
	}
}

// The same path twice is one file written once, which is what two agents
// reading one file of their own is. Only two different paths landing on one
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

	refused := agentcfg.RefuseUnwritable(hostfs.FS{}, home, os.Getuid(), "", []string{rel, rel})

	if len(refused) > 0 {
		t.Errorf("one path named twice was refused as two files: %v", refused)
	}
}

// A link out of an enrolled tree is refused: following it would apply the
// tree's group and mode to a file the enrolment was never pointed at, so a
// dotfiles copy would come out readable by the account brokered commands run
// as. In a home there is no such bound, a dotfiles repository being wherever
// the operator keeps it.
func TestALinkOutOfAnEnrolledTreeIsRefused(t *testing.T) {
	outside := t.TempDir()
	target := filepath.Join(outside, "settings.json")
	if err := os.WriteFile(target, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

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

			_, _, err := agentcfg.WriteFiles(hostfs.FS{}, nil, root, "", os.Getuid(), os.Getgid(),
				0o700, tc.inTree, render, files)

			if tc.refuse {
				if !errors.Is(err, hostfs.ErrNotOperators) {
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

// The bound is on the directory, not the file: Lstat declines to follow only
// the last component, so a symlinked parent would carry the write out of the
// tree before the leaf is looked at. Blocked at the directory, which is the
// level a run reaches first.
func TestASymlinkedParentCannotCarryTheWriteOutOfTheTree(t *testing.T) {
	outside := t.TempDir()
	const before = "{}\n"
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte(before), 0o600); err != nil {
		t.Fatal(err)
	}
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	tree := t.TempDir()
	if err := os.Symlink(outside, filepath.Join(tree, ".claude")); err != nil {
		t.Fatal(err)
	}

	_, _, err := agentcfg.WriteFiles(hostfs.FS{}, nil, tree, "", os.Getuid(), os.Getgid(),
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
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	_, _, err := agentcfg.WriteFiles(hostfs.FS{}, nil, tree, "", os.Getuid(), os.Getgid(),
		0o2770|os.ModeSetgid, true, render, files)

	if err == nil {
		t.Fatal("a creation through a symlinked parent was accepted")
	}
	if hostfs.Exists(filepath.Join(outside, "settings.json")) {
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
	render := func(agentcfg.File) ([]byte, error) { return []byte(`{"a":1}` + "\n"), nil }
	files := []agentcfg.File{{Path: ".claude/settings.json", Mode: 0o640, Merge: true}}

	if _, _, err := agentcfg.WriteFiles(hostfs.FS{}, nil, home, "", os.Getuid(), os.Getgid(),
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

// Claude Code reads CLAUDE.md and not AGENTS.md, so a tree whose own file is an
// AGENTS.md gets a CLAUDE.md of its own. Without it the agent that most needs
// the credentials section is the one agent an enrolled tree tells nothing.
func TestAnEnrolmentWritesClaudeCodeItsOwnFileBesideTheTreesAgentsFile(t *testing.T) {
	tree := t.TempDir()
	agents := filepath.Join(tree, "AGENTS.md")
	if err := os.WriteFile(agents, []byte("# Project\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    ProjectOptions{Dir: tree},
		uid:     hostfs.Keep,
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	for _, name := range []string{"AGENTS.md", "CLAUDE.md"} {
		body, err := os.ReadFile(filepath.Join(tree, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(body), agentcfg.SectionBegin) {
			t.Errorf("%s carries no credentials section:\n%s", name, body)
		}
	}
}

// An operator keeping one file for every agent links CLAUDE.md at AGENTS.md.
// The two are then one file carrying one section, rather than a pair refused as
// two writes with one survivor: every instructions file in a tree gets the same
// section, so the link loses nothing.
func TestALinkedClaudeFileIsOneFileWrittenOnce(t *testing.T) {
	tree := t.TempDir()
	agents := filepath.Join(tree, "AGENTS.md")
	link := filepath.Join(tree, "CLAUDE.md")
	if err := os.WriteFile(agents, []byte("# Project\n"), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(agents, link); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    ProjectOptions{Dir: tree},
		uid:     os.Getuid(),
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	// Asked before the write, and the write itself: the pair has to pass both.
	if err := run.refuseUnwritableFiles(); err != nil {
		t.Fatalf("the linked pair was refused before anything was written: %v", err)
	}
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}

	body, err := os.ReadFile(agents)
	if err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(string(body), agentcfg.SectionBegin); got != 1 {
		t.Errorf("the file carries %d credentials sections, want 1:\n%s", got, body)
	}
	info, err := os.Lstat(link)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Error("the link was replaced with a regular file, so the operator's " +
			"one file for every agent became two")
	}
}
