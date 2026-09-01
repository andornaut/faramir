package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostfs"
)

// The Antigravity family is two agents sharing one tree enrolment. What these
// cover is the three ways that arrangement goes wrong: a tree written
// differently depending on which half was named, a sibling reported as an agent
// nothing covers when the same files cover it, and the CLI's deny rules going
// to a file the CLI does not read.

// Enrolling either half writes the same bytes. They are told apart by what they
// keep in a home, not by anything in a tree, so a second enrolment naming the
// other must be a no-op rather than a rewrite, and an operator running both
// must not watch the file change back and forth.
func TestEitherHalfOfTheFamilyWritesTheSameTree(t *testing.T) {
	dir := t.TempDir()
	for _, file := range agentcfg.Targets["agy"].Files {
		fromCLI, err := agentcfg.AssetFor(agentcfg.Targets["agy"], file, dir)
		if err != nil {
			t.Fatal(err)
		}
		fromIDE, err := agentcfg.AssetFor(agentcfg.Targets["antigravity"], file, dir)
		if err != nil {
			t.Fatal(err)
		}
		if string(fromCLI) != string(fromIDE) {
			t.Errorf("%s differs between the two halves, so enrolling one rewrites "+
				"what the other wrote:\n%s\n---\n%s", file.Path, fromCLI, fromIDE)
		}
	}
}

// The hook registration names the guard, the dialect and a tool matcher that
// takes everything. Each of those fails silently on its own: no guard and the
// command runs unwrapped, no dialect and the reply is in a shape the agent
// ignores, and a matcher naming one tool leaves a payload the guard cannot read
// arriving on a tool nothing answers for.
func TestTheHookRegistrationNamesTheGuardAndTheDialect(t *testing.T) {
	target := agentcfg.Targets["agy"]
	var hook agentcfg.File
	// In a home: the hook is installed for the account, so it routes what the
	// agent runs in every workspace rather than in an enrolled one.
	for _, file := range target.AccountFiles {
		if strings.HasSuffix(file.Path, "hooks.json") {
			hook = file
		}
	}
	if hook.Path == "" {
		t.Fatal("nothing registers the hook, so nothing routes what the agent runs")
	}
	body, err := agentcfg.AssetFor(target, hook, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}

	var doc map[string]struct {
		Enabled    bool `json:"enabled"`
		PreToolUse []struct {
			Matcher string `json:"matcher"`
			Hooks   []struct {
				Type    string `json:"type"`
				Command string `json:"command"`
				Timeout int    `json:"timeout"`
			} `json:"hooks"`
		} `json:"PreToolUse"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the registration is not JSON the agent can read: %v\n%s", err, body)
	}
	entry, ok := doc["faramir"]
	if !ok {
		t.Fatalf("the registration is not under a name of faramir's own:\n%s", body)
	}
	if !entry.Enabled {
		t.Error("the hook is registered disabled, so nothing it would refuse is refused")
	}
	if len(entry.PreToolUse) != 1 || len(entry.PreToolUse[0].Hooks) != 1 {
		t.Fatalf("want one PreToolUse hook:\n%s", body)
	}
	if got := entry.PreToolUse[0].Matcher; got != "*" {
		t.Errorf("matcher = %q, want every tool: a payload the guard cannot read "+
			"has to refuse whatever tool it arrived on", got)
	}
	command := entry.PreToolUse[0].Hooks[0].Command
	if !strings.Contains(command, "faramir guard") {
		t.Errorf("the hook does not run the guard: %q", command)
	}
	// The family's name, not the target's: the same file is written by both.
	if !strings.Contains(command, "--host "+agentcfg.AntigravityFamily) {
		t.Errorf("the hook names no dialect the guard answers in: %q", command)
	}
	if entry.PreToolUse[0].Hooks[0].Timeout == 0 {
		t.Error("the hook has no timeout, so a guard that stops answering hangs the agent")
	}
}

// The CLI's rules go in the file the CLI reads, and refuse reading and writing
// alike. A rule the agent never reads looks exactly like one that covers
// everything.
func TestTheCLIsRulesRefuseBothVerbsInTheFileItReads(t *testing.T) {
	target := agentcfg.Targets["agy"]
	var file agentcfg.File
	for _, candidate := range target.AccountFiles {
		if strings.HasSuffix(candidate.Path, "settings.json") {
			file = candidate
		}
	}
	if file.Path != ".gemini/antigravity-cli/settings.json" {
		t.Fatalf("the rules are written to %q, which is not the file the CLI reads",
			file.Path)
	}
	if !file.Merge {
		t.Error("the rules replace the settings file rather than merging into it, " +
			"so the operator's own keys are lost")
	}

	body, err := agentcfg.RenderAccount(file.Asset, testLayout())
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
	}
	if err := json.Unmarshal(body, &doc); err != nil {
		t.Fatalf("the settings file is not JSON the agent can read: %v\n%s", err, body)
	}
	if len(doc.Permissions.Deny) == 0 {
		t.Fatalf("the settings file refuses nothing:\n%s", body)
	}
	var reads, writes int
	for _, rule := range doc.Permissions.Deny {
		switch {
		case strings.HasPrefix(rule, "read_file("):
			reads++
		case strings.HasPrefix(rule, "write_file("):
			writes++
		default:
			t.Errorf("%q is not a rule the agent parses", rule)
		}
	}
	if reads != writes {
		t.Errorf("%d read rules and %d write rules: a value the agent cannot read "+
			"is one it can still destroy", reads, writes)
	}
	// This install's own directories, at the paths the layout gives them.
	layout := testLayout()
	for _, dir := range []string{layout.ConfigDir, layout.SecretsDir(), layout.LibexecDir} {
		if !strings.Contains(string(body), "read_file("+dir+")") {
			t.Errorf("the settings file does not refuse %s", dir)
		}
	}
}

// A tree carries one set of files for both halves, so detecting the sibling in
// a tree an enrolment already covered is not finding an agent nothing redacts.
// Warning there would send an operator to enrol a second agent over the same
// bytes.
func TestEnrollingOneHalfDoesNotReportTheOtherAsUncovered(t *testing.T) {
	tree := t.TempDir()
	opts := ProjectOptions{Dir: tree, ConfigDir: t.TempDir()}
	first := &project{opts: opts, uid: hostfs.Keep, gid: hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]}}
	if err := first.agentConfig(); err != nil {
		t.Fatal(err)
	}

	// The same tree again, so the files are there to be detected.
	second := &project{opts: opts, uid: hostfs.Keep, gid: hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]}}
	if err := second.agentConfig(); err != nil {
		t.Fatal(err)
	}
	for _, warning := range second.report.Warnings {
		if strings.Contains(warning, "was not enrolled") {
			t.Errorf("the sibling was reported as an agent nothing covers, over the "+
				"files this enrolment wrote: %s", warning)
		}
	}
	// The hook is account-wide now, so an enrolment writes the tree no files at
	// all: what it leaves is the prose. Asserted so that a tree file reappearing
	// is noticed rather than assumed.
	if len(agentcfg.Targets["agy"].Files) != 0 {
		t.Errorf("the enrolment writes %d file(s) into a tree, where the guard is "+
			"installed for the account", len(agentcfg.Targets["agy"].Files))
	}
}

// The CLI reads a tree's own instructions file as well as its rules directory,
// so enrolling it must leave both. The rules file is what covers a tree whose
// own file is named something this agent does not read.
func TestTheCLIGetsBothATreeFileAndARulesFile(t *testing.T) {
	tree := t.TempDir()
	run := &project{
		opts:    ProjectOptions{Dir: tree, ConfigDir: t.TempDir()},
		uid:     hostfs.Keep,
		gid:     hostfs.Keep,
		targets: []*agentcfg.Target{agentcfg.Targets["agy"]},
	}
	if err := run.instructions(); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"AGENTS.md", agentcfg.Targets["agy"].TreeInstructions.Path} {
		body, err := os.ReadFile(filepath.Join(tree, name))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if !strings.Contains(string(body), agentcfg.SectionBegin) {
			t.Errorf("%s carries no credentials section:\n%s", name, body)
		}
	}
}

// Both halves of the family read one account-wide hook. Writing it twice is a
// second write of the same bytes and a report naming one file as two, which an
// operator reads as two files to check.
func TestTheSharedAccountHookIsWrittenOnce(t *testing.T) {
	shared := ""
	for _, file := range agentcfg.Targets["antigravity"].AccountFiles {
		for _, other := range agentcfg.Targets["agy"].AccountFiles {
			if file.Path == other.Path {
				shared = file.Path
			}
		}
	}
	if shared == "" {
		t.Fatal("the two halves share no account file, so this asserts nothing")
	}

	// Both enrolled, in the order `auto` would hand them over.
	seen := map[string]bool{}
	var written []string
	for _, name := range []string{"agy", "antigravity"} {
		for _, file := range unseenFiles(seen, agentcfg.Targets[name].AccountFiles) {
			written = append(written, file.Path)
		}
	}
	if got := strings.Count(strings.Join(written, "\n"), shared); got != 1 {
		t.Errorf("%s is written %d times, want once: %v", shared, got, written)
	}
	// And the CLI's own rules are still written: deduplicating must not drop the
	// file only one of the two has.
	if !slices.Contains(written, ".gemini/antigravity-cli/settings.json") {
		t.Errorf("the CLI's deny rules were dropped: %v", written)
	}
}

// The account-wide hook registers a program and names no path. The checks that
// ask whether every protected path is refused have to skip it: read as a rule
// file it carries none of them, and `doctor` reports every path as unrefused
// in a file that was never going to carry one.
//
// The flag is negative so that an account file added without a thought about it
// is checked rather than skipped. This pins that: every file that does render
// the path rules must leave it unset.
func TestOnlyTheRegistrationIsExemptFromTheRuleChecks(t *testing.T) {
	layout := testLayout()
	for _, name := range agentcfg.Known() {
		for _, file := range agentcfg.Targets[name].AccountFiles {
			body, err := agentcfg.RenderAccount(file.Asset, layout)
			if err != nil {
				t.Fatalf("%s %s: %v", name, file.Path, err)
			}
			// A rule file names this install's own config directory; a
			// registration names the binary and nothing else.
			carries := strings.Contains(string(body), layout.ConfigDir)
			if file.NoRules && carries {
				t.Errorf("%s: %s is exempt from the rule checks and carries rules, "+
					"so drift in it would go unreported", name, file.Path)
			}
			if !file.NoRules && !carries {
				t.Errorf("%s: %s is checked as a rule file and carries no path, so "+
					"every protected path is reported unrefused in it", name, file.Path)
			}
		}
	}
}

// faramir writes ~/.gemini/config/hooks.json for either half of the family, so
// that directory is evidence of faramir rather than of an agent. Detecting on it
// made installing for one half report the other as present and its own file as
// missing, for an agent nobody installed.
//
// An agent's own file marking itself is deliberate: it is what makes a second
// `init` refresh what the first wrote rather than decide the agent is gone. One
// agent's file marking another is not.
func TestNoAgentIsDetectedByAFileWrittenForAnother(t *testing.T) {
	written := map[string][]string{}
	for _, name := range agentcfg.Known() {
		for _, file := range agentcfg.Targets[name].AccountFiles {
			written[file.Path] = append(written[file.Path], name)
		}
	}
	for path, writers := range written {
		if len(writers) < 2 {
			continue
		}
		// A file two agents share cannot say which of them is here.
		for _, name := range agentcfg.Known() {
			for _, marker := range agentcfg.Targets[name].DetectHome {
				if strings.HasPrefix(path, strings.TrimSuffix(marker, "/")+"/") || path == marker {
					t.Errorf("%s is detected by %q, which faramir writes for %v: "+
						"installing for one reports the others as present",
						name, marker, writers)
				}
			}
		}
	}
}
