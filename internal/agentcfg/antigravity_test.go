package agentcfg

// The Antigravity family: one tree, two names, one hook.

import (
	"encoding/json"
	"strings"
	"testing"
)

// Enrolling either half writes the same bytes. They are told apart by what they
// keep in a home, not by anything in a tree, so a second enrolment naming the
// other must be a no-op rather than a rewrite, and an operator running both
// must not watch the file change back and forth.
func TestEitherHalfOfTheFamilyWritesTheSameTree(t *testing.T) {
	dir := t.TempDir()
	for _, file := range Targets["agy"].Files {
		fromCLI, err := AssetFor(Targets["agy"], file, dir)
		if err != nil {
			t.Fatal(err)
		}
		fromIDE, err := AssetFor(Targets["antigravity"], file, dir)
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
	target := Targets["agy"]
	var hook File
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
	body, err := AssetFor(target, hook, t.TempDir())
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
	if !strings.Contains(command, "--host "+antigravityFamily) {
		t.Errorf("the hook names no dialect the guard answers in: %q", command)
	}
	if entry.PreToolUse[0].Hooks[0].Timeout == 0 {
		t.Error("the hook has no timeout, so a guard that stops answering hangs the agent")
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
	for _, name := range Known() {
		for _, file := range Targets[name].AccountFiles {
			written[file.Path] = append(written[file.Path], name)
		}
	}
	for path, writers := range written {
		if len(writers) < 2 {
			continue
		}
		// A file two agents share cannot say which of them is here.
		for _, name := range Known() {
			for _, marker := range Targets[name].DetectHome {
				if strings.HasPrefix(path, strings.TrimSuffix(marker, "/")+"/") || path == marker {
					t.Errorf("%s is detected by %q, which faramir writes for %v: "+
						"installing for one reports the others as present",
						name, marker, writers)
				}
			}
		}
	}
}
