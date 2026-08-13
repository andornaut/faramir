package install

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// names is what resolveAgents settled on, for a test that cares which agents
// rather than which targets.
func names(t *testing.T, values []string, scope agentScope, dir string) []string {
	t.Helper()
	targets, err := resolveAgents(values, scope, dir)
	if err != nil {
		t.Fatal(err)
	}
	out := []string{}
	for _, target := range targets {
		out = append(out, target.name)
	}
	return out
}

// Naming no agent is naming auto, which configures what is there and nothing
// else.  An empty directory is therefore no agents, not a default one: writing
// configuration for an agent the operator does not run is not this command's
// to do.
func TestAgentsDefaultToWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	if got := names(t, nil, scopeTree, dir); len(got) != 0 {
		t.Errorf("resolveAgents(nil) in an empty tree = %v, want none", got)
	}
	if err := os.Mkdir(filepath.Join(dir, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := names(t, nil, scopeTree, dir); !reflect.DeepEqual(got, []string{"gemini"}) {
		t.Errorf("resolveAgents(nil) = %v, want [gemini]", got)
	}
}

// An unknown name stops the run rather than being skipped, which would leave a
// project the operator believes is covered.
func TestUnknownAgentIsRefused(t *testing.T) {
	if _, err := resolveAgents([]string{"claude", "nosuchagent"}, scopeTree, t.TempDir()); err == nil {
		t.Error("an unknown agent was accepted")
	}
	// The error names auto as well, that being a value the flag takes and not
	// an agent anybody could look up.
	_, err := resolveAgents([]string{"nosuchagent"}, scopeTree, t.TempDir())
	if err == nil || !strings.Contains(err.Error(), "auto") {
		t.Errorf("the error does not offer auto: %v", err)
	}
}

// Repeats collapse, and the order is fixed rather than the order given: auto
// contributes what it detected and the flags contribute what was typed, so
// "the order given" is not a thing the result has.
func TestAgentsDeduplicate(t *testing.T) {
	got := names(t, []string{"gemini", "claude", "gemini"}, scopeTree, t.TempDir())
	if !reflect.DeepEqual(got, []string{"claude", "gemini"}) {
		t.Errorf("names = %v, want [claude gemini], deduplicated and ordered", got)
	}
}

// auto and a name compose: what is installed, plus the one asked for.  No rule
// about which wins, because naming an agent only ever adds it.
func TestAutoAndANameAreUnioned(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".gemini"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := names(t, []string{AgentAuto, "pi"}, scopeTree, dir)
	if !reflect.DeepEqual(got, []string{"gemini", "pi"}) {
		t.Errorf("names = %v, want [gemini pi]", got)
	}
}

// A name alone configures that agent whether or not anything is there, which
// is what makes it possible to set one up before installing it.
func TestANamedAgentDoesNotHaveToBePresent(t *testing.T) {
	got := names(t, []string{"pi"}, scopeTree, t.TempDir())
	if !reflect.DeepEqual(got, []string{"pi"}) {
		t.Errorf("names = %v, want [pi] in an empty tree", got)
	}
}

// The two commands ask the same question of different places.  opencode is the
// case that separates them: opencode.json beside a project, .config/opencode
// under a home.
func TestAutoLooksWhereTheScopeSays(t *testing.T) {
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "opencode.json"), []byte("{}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".config", "opencode"), 0o700); err != nil {
		t.Fatal(err)
	}

	if got := names(t, nil, scopeTree, tree); !reflect.DeepEqual(got, []string{"opencode"}) {
		t.Errorf("tree scope = %v, want [opencode]", got)
	}
	if got := names(t, nil, scopeHome, home); !reflect.DeepEqual(got, []string{"opencode"}) {
		t.Errorf("home scope = %v, want [opencode]", got)
	}
	// And neither answers the other's question: a home marker in a tree is not
	// evidence, nor the other way round.
	if got := names(t, nil, scopeHome, tree); len(got) != 0 {
		t.Errorf("home scope found %v in a tree laid out as a project", got)
	}
	if got := names(t, nil, scopeTree, home); len(got) != 0 {
		t.Errorf("tree scope found %v in a home", got)
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

// Every merged file has to be JSON once rendered, an interpolated path holding
// a quote or backslash being a file the agent cannot load.  Rendered the way
// each half is in production: a tree's file against the target's own data, an
// account file against the install layout.
func TestMergedAgentAssetsAreJSON(t *testing.T) {
	layout := testLayout()
	check := func(t *testing.T, name string, file agentFile, body []byte) {
		t.Helper()
		var into any
		if err := json.Unmarshal(body, &into); err != nil {
			t.Errorf("%s: %s is not JSON: %v", name, file.asset, err)
		}
	}
	for name, target := range agentTargets {
		for _, file := range target.files {
			if !file.merge {
				continue
			}
			body, err := assetFor(target, file, layout.ConfigDir)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			check(t, name, file, body)
		}
		for _, file := range target.accountFiles {
			if !file.merge {
				continue
			}
			body, err := render(file.asset, layout)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			check(t, name, file, body)
		}
	}
}

// A plugin naming another host asks the guard for a dialect that host does not
// speak, and fails closed on every command in the project.
//
// Rendered rather than read, and selected by the file it is installed as rather
// than by the asset it comes from: the host is interpolated and every asset is
// now a template, so reading one finds the placeholder and asserts nothing.
func TestPluginAssetsNameTheirOwnHost(t *testing.T) {
	hosts := 0
	for name, target := range agentTargets {
		for _, file := range target.files {
			if !strings.HasSuffix(file.path, ".js") && !strings.HasSuffix(file.path, ".ts") {
				continue
			}
			hosts++
			body, err := assetFor(target, file, testLayout().ConfigDir)
			if err != nil {
				t.Fatal(err)
			}
			if want := `const HOST = "` + name + `"`; !strings.Contains(string(body), want) {
				t.Errorf("%s: %s does not name %s", name, file.asset, want)
			}
		}
	}
	// Counted, so a selector matching nothing fails here rather than passing as
	// a loop that ran zero times.
	if want := 3; hosts != want {
		t.Errorf("checked %d plugin hosts, want %d: the selector no longer matches "+
			"what is installed", hosts, want)
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
	ours, err := render("agent/permissions.json.tmpl", testLayout())
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

// Detection is what auto acts on, so this covers the finding rather than the
// deciding: an empty tree yields nothing, and a marker yields its agent.
func TestDetectionFindsAgentDirectories(t *testing.T) {
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
}
