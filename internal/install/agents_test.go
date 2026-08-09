package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Naming no agent enrols Claude Code.
func TestAgentsDefaultToClaude(t *testing.T) {
	got, err := resolveAgents(nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].name != "claude" {
		t.Errorf("resolveAgents(nil) = %v, want claude alone", got)
	}
}

// An unknown name stops the run rather than being skipped, which would leave a
// project the operator believes is covered.
func TestUnknownAgentIsRefused(t *testing.T) {
	if _, err := resolveAgents([]string{"claude", "nosuchagent"}); err == nil {
		t.Error("an unknown agent was accepted")
	}
}

// Repeats collapse: writing twice reports the second as unchanged, which reads
// as a failure to write.
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

// What enrolling costs differs by agent: Claude Code's hook must approve a
// rewritten command, Gemini CLI has no approval to give.
func TestOnlyClaudeAutoApprovesBash(t *testing.T) {
	if !agentTargets["claude"].autoApprovesBash {
		t.Error("claude does not record that it auto-approves Bash")
	}
	if agentTargets["gemini"].autoApprovesBash {
		t.Error("gemini claims to auto-approve Bash; it has no allow to return")
	}
}

// A typo here is an enrolment that fails after the tree's ownership has already
// changed.
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

// Every merged file has to be JSON.  A .tmpl is rendered first, an interpolated
// path holding a quote or backslash being a file the agent cannot load.
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

// The plugin ships beside the guard rather than being generated from it, so a
// name that does not match the target fails closed on every command.
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

// This install's own directories, not the compiled defaults, which on a moved
// config would protect a directory that does not exist.
func TestAccountRulesNameTheInstalledDirectories(t *testing.T) {
	layout := testLayout()
	for _, name := range []string{"opencode", "kilocode"} {
		for _, file := range agentTargets[name].accountFiles {
			body, err := render(file.asset, layout)
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{layout.ConfigDir, layout.SecretsDir(), layout.LibexecDir} {
				if !strings.Contains(string(body), dir+"/*") {
					t.Errorf("%s: %s does not refuse %s", name, file.asset, dir)
				}
			}
			// A refs file names secrets and holds none, which is why the dotenv
			// rules are anchored on the dot.
			if strings.Contains(string(body), `"*.env`) {
				t.Errorf("%s: %s refuses any name ending in .env, which includes faramir.env",
					name, file.asset)
			}
		}
	}
}

// Keys inside a config the operator owns, as an object of patterns: a merge
// that dropped a sibling would take away a rule, a server or a model.
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
	// Their catch-all survives, and faramir writes none of its own.
	if read["*"] != "allow" {
		t.Errorf("the operator's catch-all was lost: %s", merged)
	}
	if read["*age.key"] != "deny" {
		t.Errorf("faramir's rules were not added: %s", merged)
	}
	// faramir's wins on a shared pattern; the rest is carried through.
	if read["src/*.key"] != "allow" {
		t.Errorf("an unrelated rule of the operator's was changed: %s", merged)
	}
}

// Configured for an agent is not the same as written to by faramir: an opencode
// project has its directory long before the plugin file.
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

// Detection reports and never enrols: a directory left behind by trying an
// agent is not a decision to enrol it.
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
	// Detection feeds a report; resolveAgents decides.
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
