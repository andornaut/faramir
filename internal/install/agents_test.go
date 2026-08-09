package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Naming no agent enrols Claude Code, so a command written before --agent
// existed keeps doing what it did.
func TestAgentsDefaultToClaude(t *testing.T) {
	got, err := resolveAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "claude" {
		t.Errorf("resolveAgents(nil) = %v, want claude alone", got)
	}
}

// An unknown name stops the run rather than being skipped. A run that enrolled
// nothing and mentioned it in a line nobody read leaves an operator believing a
// project is covered when it is not.
func TestUnknownAgentIsRefused(t *testing.T) {
	if _, err := resolveAgents([]string{"claude", "nosuchagent"}); err == nil {
		t.Error("an unknown agent was accepted")
	}
}

// Repeats collapse: enrolling the same agent twice writes its files twice and
// reports the second as unchanged, which reads as a failure to write.
func TestAgentsDeduplicate(t *testing.T) {
	got, err := resolveAgents([]string{"gemini", "claude", "gemini"})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, target := range got {
		names = append(names, target.name)
	}
	if !reflect.DeepEqual(names, []string{"gemini", "claude"}) {
		t.Errorf("names = %v, want [gemini claude] in the order given", names)
	}
}

// What enrolling costs differs by agent, and the warning a run prints has to be
// the truth for the agent it just enrolled. On Claude Code a rewritten command
// matches no permission rule and the hook must approve it; on Gemini CLI there
// is no approval to give, so the prompts are untouched.
func TestOnlyClaudeAutoApprovesBash(t *testing.T) {
	if !agentTargets["claude"].autoApprovesBash {
		t.Error("claude does not record that it auto-approves Bash")
	}
	if agentTargets["gemini"].autoApprovesBash {
		t.Error("gemini claims to auto-approve Bash; it has no allow to return")
	}
}

// Every descriptor names assets that exist. A typo here is an enrolment that
// fails after the tree's ownership has already been changed.
func TestAgentAssetsExist(t *testing.T) {
	for name, target := range agentTargets {
		if len(target.files) == 0 {
			t.Errorf("%s writes nothing", name)
		}
		if len(target.detect) == 0 {
			t.Errorf("%s cannot be detected, so a tree carrying it is never reported", name)
		}
		for _, file := range append(append([]agentFile{}, target.files...), target.accountFiles...) {
			if _, err := readAsset(file.asset); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// Every file faramir merges into has to be JSON, since that is what the merge
// parses. A .tmpl among them is rendered first: an interpolated path holding a
// quote or a backslash would be a file the agent cannot load.
func TestMergedAgentAssetsAreJSON(t *testing.T) {
	layout := testLayout()
	for name, target := range agentTargets {
		for _, file := range append(append([]agentFile{}, target.files...), target.accountFiles...) {
			if !file.merge {
				continue
			}
			body, err := render(file.asset, layout)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			var into any
			if err := json.Unmarshal(body, &into); err != nil {
				t.Errorf("%s: %s is not JSON: %v", name, file.asset, err)
			}
		}
	}
}

// The plugin agents are told which dialect to ask for, in a file that ships
// beside the guard rather than being generated from it. A name that does not
// match the target is a plugin the guard refuses to answer, and by failing
// closed that is every command in the project.
func TestPluginAssetsNameTheirOwnHost(t *testing.T) {
	for name, target := range agentTargets {
		for _, file := range target.files {
			if !strings.HasSuffix(file.asset, ".js") {
				continue
			}
			body, err := readAsset(file.asset)
			if err != nil {
				t.Fatal(err)
			}
			if want := `const HOST = "` + name + `"`; !strings.Contains(string(body), want) {
				t.Errorf("%s: %s does not name %s", name, file.asset, want)
			}
		}
	}
}

// The account-level rules refuse this install's own directories, not the
// compiled defaults: a host whose config and store were moved into a home would
// otherwise have a rule protecting a directory that does not exist.
func TestAccountRulesNameTheInstalledDirectories(t *testing.T) {
	layout := testLayout()
	for _, name := range []string{"opencode", "kilocode"} {
		for _, file := range agentTargets[name].accountFiles {
			body, err := render(file.asset, layout)
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{layout.ConfigDir, layout.SecretsDir, layout.LibexecDir} {
				if !strings.Contains(string(body), dir+"/*") {
					t.Errorf("%s: %s does not refuse %s", name, file.asset, dir)
				}
			}
			// A refs file is meant to be read: it names secrets and holds none.
			// The dotenv rules are anchored on the dot for that reason.
			if strings.Contains(string(body), `"*.env`) {
				t.Errorf("%s: %s refuses any name ending in .env, which includes faramir.env",
					name, file.asset)
			}
		}
	}
}

// The account-level rules are keys inside a config the operator owns, not a
// file of faramir's, and on these agents they are an object of patterns rather
// than a list. A merge that dropped a sibling key would take away a permission
// rule, an MCP server or a model the operator configured.
func TestAccountRulesMergeIntoTheOperatorsConfig(t *testing.T) {
	ours, err := render("agent/opencode/permissions.json.tmpl", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	existing := []byte(`{
	  "model": "anthropic/claude-opus-4",
	  "mcp": {"theirs": {"type": "local", "command": ["their-server"]}},
	  "permission": {"bash": {"*": "ask"}, "read": {"*": "allow", "src/*.key": "allow"}}
	}`)
	merged, err := mergeJSON(existing, ours)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(t, merged)
	if got["model"] != "anthropic/claude-opus-4" {
		t.Errorf("the operator's model was lost: %s", merged)
	}
	permission := got["permission"].(map[string]any)
	if _, kept := permission["bash"]; !kept {
		t.Errorf("the operator's bash rules were lost: %s", merged)
	}
	read := permission["read"].(map[string]any)
	// Their catch-all survives, and faramir writes none of its own: a default
	// this is not entitled to loosen or tighten.
	if read["*"] != "allow" {
		t.Errorf("the operator's catch-all was lost: %s", merged)
	}
	if read["*age.key"] != "deny" {
		t.Errorf("faramir's rules were not added: %s", merged)
	}
	// Where the two name the same pattern faramir's wins, and everything else
	// of theirs is carried through.
	if read["src/*.key"] != "allow" {
		t.Errorf("an unrelated rule of the operator's was changed: %s", merged)
	}
}

// Detection reports a tree that is configured for an agent, which is not the
// same as one faramir has already written to: an opencode project has its own
// directory long before it has the plugin file this installs.
func TestDetectionFindsAnAgentsOwnConfiguration(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "opencode.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(dir, ".kilo"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := detectedAgents(dir); !reflect.DeepEqual(got, []string{"kilocode", "opencode"}) {
		t.Errorf("detectedAgents = %v, want [kilocode opencode]", got)
	}
}

// Detection reports and never enrols. A directory left behind by trying an
// agent once is not a decision to enrol it, and on some agents enrolling trades
// away every Bash prompt in the project.
func TestDetectionFindsAgentDirectoriesWithoutEnrolling(t *testing.T) {
	dir := t.TempDir()
	if got := detectedAgents(dir); len(got) != 0 {
		t.Errorf("detected %v in an empty tree", got)
	}
	if err := os.Mkdir(filepath.Join(dir, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := detectedAgents(dir); !reflect.DeepEqual(got, []string{"gemini"}) {
		t.Errorf("detectedAgents = %v, want [gemini]", got)
	}
	// Still not enrolled: detection feeds a report, and resolveAgents is what
	// decides, from what the operator asked for.
	targets, err := resolveAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, target := range targets {
		if target.name == "gemini" {
			t.Error("a .gemini directory enrolled gemini by itself")
		}
	}
}
