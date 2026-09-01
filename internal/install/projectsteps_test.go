package install

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// The irreversible step goes first and everything else runs after it: the share
// chowns and chmods every file in the tree, so a file written before the walk
// is one the walk then regroups. That every step is named is
// TestEveryStepIsNamedAndRunsSomething.
func TestTheShareIsAnEnrolmentsFirstStep(t *testing.T) {
	steps := (&project{}).steps()
	if len(steps) == 0 {
		t.Fatal("an enrolment has no steps")
	}
	if steps[0].name != "share tree" {
		t.Errorf("the first step is %q, want the share", steps[0].name)
	}
}

// The ids are resolved in preflight, and a dry run is allowed to reach it on a
// host that has not been provisioned: it needs no privilege, and the group it
// would share with is one `init` creates. What it must not do is fall back to
// an owner, which is what 0 would mean and what `keep` avoids: uid 0 hands the
// operator's own file to root, and keep leaves ownership alone.
func TestUnresolvedIDsAreLeftAloneRatherThanTakenByRoot(t *testing.T) {
	run := &project{opts: ProjectOptions{AgentUser: "nosuchuser-faramir", DryRun: true}}
	run.uid, run.gid = 12345, 12345

	if err := run.resolveIDs(); err != nil {
		t.Fatalf("a dry run against an unprovisioned host failed: %v", err)
	}
	if run.uid != 12345 || run.gid != 12345 {
		t.Errorf("uid, gid = %d, %d: a lookup that failed overwrote them", run.uid, run.gid)
	}
	// And the real path still refuses, an enrolment that cannot name the owner
	// having nothing to hand the tree to.
	named := &project{opts: ProjectOptions{AgentUser: "nosuchuser-faramir"}}
	if err := named.resolveIDs(); err == nil {
		t.Error("an enrolment proceeded with an account that does not exist")
	}
}

// Project starts them at keep, so a write that somehow lands before preflight
// leaves ownership as it is rather than giving the file to root.
func TestAnEnrolmentStartsWithNoOwnerToImpose(t *testing.T) {
	report, err := Project(ProjectOptions{
		Dir: t.TempDir(), AgentUser: "operator", ClientGroup: "nosuchgroup",
		ConfigDir: t.TempDir(), DryRun: true,
	})
	if err != nil {
		t.Fatalf("a dry run against an unprovisioned host failed: %v\n%+v", err, report)
	}
	if !strings.Contains(strings.Join(stepNames(report), " "), "share tree") {
		t.Errorf("a dry run reported no share step: %v", stepNames(report))
	}
}

func stepNames(report ProjectReport) []string {
	out := make([]string, 0, len(report.Steps))
	for _, step := range report.Steps {
		out = append(out, step.Name)
	}
	return out
}

// The hook and every plugin exec this binary, and all of them fail closed. A
// tree enrolled where it is absent has agents that refuse every command in it
// rather than running one unredacted, so the enrolment says so.
func TestEnrolmentWarnsWhenTheBinaryTheHookExecsIsAbsent(t *testing.T) {
	tree := t.TempDir()

	absent := &project{opts: ProjectOptions{Dir: tree}}
	absent.warnMissingBinary(filepath.Join(t.TempDir(), "faramir"))
	warnings := strings.Join(absent.report.Warnings, "\n")
	if !strings.Contains(warnings, "not installed") || !strings.Contains(warnings, tree) {
		t.Errorf("a missing binary was not reported: %v", absent.report.Warnings)
	}

	installed := filepath.Join(t.TempDir(), "faramir")
	if err := os.WriteFile(installed, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	present := &project{opts: ProjectOptions{Dir: tree}}
	present.warnMissingBinary(installed)
	if len(present.report.Warnings) != 0 {
		t.Errorf("an installed binary was reported as missing: %v", present.report.Warnings)
	}
}

// An enrolment can say a step was not evaluated, which is what a dry run and a
// step with no subject both need: a step missing from the report reads as one
// that never existed.
func TestAnEnrolmentCanRecordASkippedStep(t *testing.T) {
	run := &project{}
	run.skip("share tree", "dry run")

	if len(run.report.Steps) != 1 || !run.report.Steps[0].Skipped {
		t.Fatalf("skip recorded %+v, want one skipped step", run.report.Steps)
	}
	if run.report.Changed {
		t.Error("a skipped step marked the report changed")
	}
}

// A directory created for an agent's files in a tree is shared like the rest of
// it. The files go in group-readable because the tree is shared with the
// client group; 0700 above them would make an enrolled tree's own configuration
// the one thing in it that group cannot reach, until a later run's walk widened
// it and reported a change on what reads as a no-op re-enrolment.
//
// Through agentConfig rather than through writeAgentFiles, so what is asserted
// is the mode this command asks for and not the one the test passed in.
func TestAgentDirectoriesInATreeAreSharedLikeTheRest(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     hostfs.Keep,
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	if err := run.agentConfig(); err != nil {
		t.Fatal(err)
	}

	info, err := os.Stat(filepath.Join(tree, ".claude"))
	if err != nil {
		t.Fatal(err)
	}
	if got := info.Mode().Perm() & 0o070; got != 0o070 {
		t.Errorf(".claude is %04o: the client group cannot enter it, so the "+
			"group-readable file inside reaches nothing", info.Mode().Perm())
	}
	if info.Mode()&os.ModeSetgid == 0 {
		t.Errorf(".claude is %v, want setgid as the share leaves every other "+
			"directory in the tree", info.Mode())
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

// The refusals are asked before the share, which chowns and chmods every file
// in the tree and cannot be undone. Finding out afterwards that a settings
// file is not the operator's is finding out too late.
func TestAnEnrolmentRefusesAnUnwritableFileBeforeSharing(t *testing.T) {
	tree := t.TempDir()
	// A link out of the tree, which the write would refuse.
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "settings.json"),
		filepath.Join(tree, ".claude", "settings.local.json")); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts:    ProjectOptions{Dir: tree},
		uid:     os.Getuid(),
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["claude"]},
	}

	err := run.refuseUnwritableFiles()

	if err == nil {
		t.Fatal("an enrolment accepted a file its own write would refuse")
	}
	if !strings.Contains(err.Error(), ".claude/settings.local.json") {
		t.Errorf("the error does not name the file: %v", err)
	}
	// Nothing was written and nothing shared: this ran before either.
	if body, readErr := os.ReadFile(filepath.Join(outside, "settings.json")); readErr != nil {
		t.Fatal(readErr)
	} else if string(body) != "{}\n" {
		t.Errorf("the file outside the tree was written:\n%s", body)
	}
}

// And preflight is where it is asked, which is what puts it before the share.
// Asserting the function alone would pass with nothing calling it.
func TestPreflightRefusesBeforeAnyStepRuns(t *testing.T) {
	me, err := user.Current()
	if err != nil {
		t.Skip("cannot name this account")
	}
	tree := t.TempDir()
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "settings.json"), []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(tree, ".claude"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "settings.json"),
		filepath.Join(tree, ".claude", "settings.local.json")); err != nil {
		t.Fatal(err)
	}
	run := &project{
		opts: ProjectOptions{
			Dir: tree, AgentUser: me.Username, ClientGroup: "shared",
			DryRun: true,
		},
		uid: hostfs.Keep, gid: hostfs.Keep,
	}
	run.report = ProjectReport{ClientGroup: "shared"}

	err = run.preflight()

	if err == nil {
		t.Fatal("preflight accepted a tree whose settings file the write would refuse")
	}
	if !strings.Contains(err.Error(), ".claude/settings.local.json") {
		t.Errorf("the error does not name the file: %v", err)
	}
	// The share is step one and this ran before any step: the tree is untouched.
	info, statErr := os.Stat(tree)
	if statErr != nil {
		t.Fatal(statErr)
	}
	if info.Mode()&os.ModeSetgid != 0 {
		t.Error("the tree was shared before the refusal")
	}
}
