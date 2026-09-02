package agentcfg

// What the targets declare about the agents.

import (
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// The two plugin hosts install the same rules, and what makes that true is that
// they name one asset rather than two files kept in step by hand. Asserted
// against the targets: rendering both and comparing would compare one file with
// itself and pass however the targets were wired.
func TestBothPluginHostsGetTheSameRules(t *testing.T) {
	assets := map[string][]string{}
	for _, name := range []string{"opencode", "kilocode"} {
		for _, file := range Targets[name].AccountFiles {
			assets[name] = append(assets[name], file.Asset)
		}
	}
	if len(assets["opencode"]) == 0 {
		t.Fatal("opencode writes no account-wide rules")
	}
	if !slices.Equal(assets["opencode"], assets["kilocode"]) {
		t.Errorf("opencode writes %v and Kilo Code writes %v, so the two lists can "+
			"drift", assets["opencode"], assets["kilocode"])
	}
}

// A file two agents read is named once when a run refuses it: an operator gets
// a list of what to fix, and one file listed twice reads as two. No shipped
// pair shares a file, so the targets here are built rather than looked up.
func TestAFileTwoAgentsReadIsNamedOnce(t *testing.T) {
	const shared = "AGENTS.md"
	first := &Target{Name: "first", HomeInstructions: shared}
	second := &Target{Name: "second", HomeInstructions: shared}

	paths := HomeEditedPaths([]*Target{first, second})

	if n := slices.Index(paths, shared); n < 0 {
		t.Fatalf("paths = %v, want the file they share", paths)
	}
	if n := len(paths); n != 1 {
		t.Errorf("paths = %v, want the shared file named once", paths)
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
	for _, name := range Known() {
		if len(Targets[name].AccountFiles) == 0 {
			t.Errorf("%s writes nothing into a home, so a tree nobody enrolled has "+
				"none of its refusals", name)
		}
	}
}

// Nothing is auto-approved on its behalf: there is no allow to return, and a
// report claiming the Bash trade was taken would be naming a cost this agent
// does not pay.
func TestAnAgentWithNoHookTakesNothingAway(t *testing.T) {
	target := Targets["antigravity"]
	if target.AutoApprovesBash {
		t.Error("antigravity claims to auto-approve Bash, having no hook that could")
	}
	// What it writes account-wide is a hook, not a permission rule: its lists are
	// the IDE's own state, and an install that wrote one would be writing a file
	// the agent does not read.
	for _, file := range target.AccountFiles {
		if !strings.HasSuffix(file.Path, "hooks.json") {
			t.Errorf("antigravity writes %s account-wide, which is not a file it "+
				"reads: its permission lists are the IDE's own state", file.Path)
		}
	}
}

// A path outside the home, or one an agent does not read, is a section written
// where nothing loads it. Checked here because it is not visible at runtime:
// the file is written, and the agent never says anything different.
func TestEveryHomeInstructionsPathIsRelativeToTheHome(t *testing.T) {
	for _, name := range Known() {
		path := Targets[name].HomeInstructions
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
