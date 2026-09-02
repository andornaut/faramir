package install

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
)

// The Antigravity family is two agents sharing one tree enrolment. What these
// cover is the ways that arrangement goes wrong in an install: the CLI's deny
// rules going to a file the CLI does not read, and the shared hook being
// written twice or exempted from more than its registration.

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
