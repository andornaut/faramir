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

// The same directory in the agent account's home is not shared with anybody.
func TestAgentDirectoriesInAHomeStayPrivate(t *testing.T) {
	home := t.TempDir()

	initHome(t, home, "claude")

	info, err := os.Stat(filepath.Join(home, ".claude"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm(); got != 0o700 {
		t.Errorf(".claude is %04o, want 0700: nothing else has business in it", got)
	}
}
