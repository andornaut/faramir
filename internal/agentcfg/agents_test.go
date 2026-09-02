package agentcfg

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/layouttest"
)

// names is what resolveAgents settled on, for a test that cares which agents
// rather than which targets.
func names(t *testing.T, values []string, scope Scope, dir string) []string {
	t.Helper()
	targets, err := Resolve(values, scope, dir, "")
	if err != nil {
		t.Fatal(err)
	}
	out := make([]string, 0, len(targets))
	for _, target := range targets {
		out = append(out, target.Name)
	}
	return out
}

// Naming no agent is naming auto, which configures what is there and nothing
// else. An empty directory is therefore no agents, not a default one: writing
// configuration for an agent the operator does not run is not this command's
// to do.
func TestAgentsDefaultToWhatIsThere(t *testing.T) {
	dir := t.TempDir()
	if got := names(t, nil, ScopeTree, dir); len(got) != 0 {
		t.Errorf("resolveAgents(nil) in an empty tree = %v, want none", got)
	}
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := names(t, nil, ScopeTree, dir); !reflect.DeepEqual(got, []string{"claude"}) {
		t.Errorf("resolveAgents(nil) = %v, want [claude]", got)
	}
}

// An unknown name stops the run rather than being skipped, which would leave a
// project the operator believes is covered.
func TestUnknownAgentIsRefused(t *testing.T) {
	if _, err := Resolve([]string{"claude", "nosuchagent"}, ScopeTree, t.TempDir(), ""); err == nil {
		t.Error("an unknown agent was accepted")
	}
	// The error names auto as well, that being a value the flag takes and not
	// an agent anybody could look up.
	_, err := Resolve([]string{"nosuchagent"}, ScopeTree, t.TempDir(), "")
	if err == nil || !strings.Contains(err.Error(), "auto") {
		t.Errorf("the error does not offer auto: %v", err)
	}
}

// Repeats collapse, and the order is fixed rather than the order given: auto
// contributes what it detected and the flags contribute what was typed, so
// "the order given" is not a thing the result has.
func TestAgentsDeduplicate(t *testing.T) {
	got := names(t, []string{"pi", "claude", "pi"}, ScopeTree, t.TempDir())
	if !reflect.DeepEqual(got, []string{"claude", "pi"}) {
		t.Errorf("names = %v, want [claude pi], deduplicated and ordered", got)
	}
}

// auto and a name compose: what is installed, plus the one asked for. No rule
// about which wins, because naming an agent only ever adds it.
func TestAutoAndANameAreUnioned(t *testing.T) {
	dir := t.TempDir()
	if err := os.Mkdir(filepath.Join(dir, ".claude"), 0o700); err != nil {
		t.Fatal(err)
	}
	got := names(t, []string{Auto, "pi"}, ScopeTree, dir)
	if !reflect.DeepEqual(got, []string{"claude", "pi"}) {
		t.Errorf("names = %v, want [claude pi]", got)
	}
}

// A name alone configures that agent whether or not anything is there, which
// is what makes it possible to set one up before installing it.
func TestANamedAgentDoesNotHaveToBePresent(t *testing.T) {
	got := names(t, []string{"pi"}, ScopeTree, t.TempDir())
	if !reflect.DeepEqual(got, []string{"pi"}) {
		t.Errorf("names = %v, want [pi] in an empty tree", got)
	}
}

// The two commands ask the same question of different places. opencode is the
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

	if got := names(t, nil, ScopeTree, tree); !reflect.DeepEqual(got, []string{"opencode"}) {
		t.Errorf("tree scope = %v, want [opencode]", got)
	}
	if got := names(t, nil, ScopeHome, home); !reflect.DeepEqual(got, []string{"opencode"}) {
		t.Errorf("home scope = %v, want [opencode]", got)
	}
	// And neither answers the other's question: a home marker in a tree is not
	// evidence, nor the other way round.
	if got := names(t, nil, ScopeHome, tree); len(got) != 0 {
		t.Errorf("home scope found %v in a tree laid out as a project", got)
	}
	if got := names(t, nil, ScopeTree, home); len(got) != 0 {
		t.Errorf("tree scope found %v in a home", got)
	}
}

// What enrolling costs differs by agent. Claude Code and Codex return a
// permission decision, so the hook that rewrites a command must also approve
// it, and that approval covers every command the deny list does not name. Every
// other agent has no allow to return, so its prompts are untouched.
func TestOnlyDecidingHostsAutoApproveBash(t *testing.T) {
	decides := map[string]bool{"claude": true, "codex": true}
	for name := range decides {
		if !Targets[name].AutoApprovesBash {
			t.Errorf("%s does not record that it auto-approves Bash", name)
		}
	}
	for _, name := range Known() {
		if !decides[name] && Targets[name].AutoApprovesBash {
			t.Errorf("%s claims to auto-approve Bash; it has no allow to return", name)
		}
	}
}

// A typo here is an enrolment that fails after the tree's ownership has already
// changed.
//
// The roster is pinned here as well, and this is the one place it is: tests
// across this package loop over knownAgents() and agentTargets, and an empty
// roster would turn every one of them into a pass having checked nothing.
func TestAgentAssetsExist(t *testing.T) {
	if len(Targets) == 0 || len(Known()) != len(Targets) {
		t.Fatalf("knownAgents() has %d entries and agentTargets %d: every loop over "+
			"either checks that many agents", len(Known()), len(Targets))
	}
	for name, target := range Targets {
		// Tree or home. Five agents write nothing into a tree: what guards them is
		// installed for the account, so an enrolment leaves them the prose alone.
		if len(target.Files)+len(target.AccountFiles) == 0 {
			t.Errorf("%s writes nothing", name)
		}
		if len(target.Detect) == 0 {
			t.Errorf("%s cannot be detected, so a tree carrying it is never reported", name)
		}
		for _, file := range append(append([]File{}, target.Files...), target.AccountFiles...) {
			if _, err := Asset(file.Asset); err != nil {
				t.Errorf("%s: %v", name, err)
			}
		}
	}
}

// Every merged file has to be JSON once rendered, an interpolated path holding
// a quote or backslash being a file the agent cannot load. Rendered the way
// each half is in production: a tree's file against the target's own data, an
// account file against the install layout.
func TestMergedAgentAssetsAreJSON(t *testing.T) {
	layout := layouttest.Layout()
	check := func(t *testing.T, name string, file File, body []byte) {
		t.Helper()
		var into any
		if err := json.Unmarshal(body, &into); err != nil {
			t.Errorf("%s: %s is not JSON: %v", name, file.Asset, err)
		}
	}
	for name, target := range Targets {
		for _, file := range target.Files {
			if !file.Merge {
				continue
			}
			body, err := AssetFor(target, file, layout.ConfigDir)
			if err != nil {
				t.Fatalf("%s: %v", name, err)
			}
			check(t, name, file, body)
		}
		for _, file := range target.AccountFiles {
			if !file.Merge {
				continue
			}
			body, err := RenderAccount(file.Asset, layout)
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
	for name, target := range Targets {
		// In a home now, not a tree: the plugin and the extension are installed
		// for the account, so this looks where they are.
		for _, file := range append(append([]File{}, target.Files...), target.AccountFiles...) {
			if !strings.HasSuffix(file.Path, ".js") && !strings.HasSuffix(file.Path, ".ts") {
				continue
			}
			hosts++
			body, err := AssetFor(target, file, layouttest.Layout().ConfigDir)
			if err != nil {
				t.Fatal(err)
			}
			if want := `const HOST = "` + name + `"`; !strings.Contains(string(body), want) {
				t.Errorf("%s: %s does not name %s", name, file.Asset, want)
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
	layout := layouttest.Layout()
	// The two plugin hosts, which spell a directory the same way. Antigravity's
	// spelling is its own and is asserted where its rules are.
	for _, name := range []string{"opencode", "kilocode"} {
		for _, file := range Targets[name].AccountFiles {
			// The rule file, not the plugin beside it: the plugin carries no paths
			// of its own any more, asking the guard instead.
			if file.NoRules {
				continue
			}
			body, err := RenderAccount(file.Asset, layout)
			if err != nil {
				t.Fatal(err)
			}
			for _, dir := range []string{layout.ConfigDir, layout.SecretsDir(), layout.LibexecDir} {
				if !strings.Contains(string(body), dir+"/*") {
					t.Errorf("%s: %s does not refuse %s", name, file.Asset, dir)
				}
			}
			// A refs file names secrets and holds none, which is why the dotenv
			// rules are anchored on the dot.
			if strings.Contains(string(body), `"*.env`) {
				t.Errorf("%s: %s refuses any name ending in .env, which includes faramir.env",
					name, file.Asset)
			}
		}
	}
}

// Keys inside a config the operator owns, as an object of patterns: a merge
// that dropped a sibling would take away a rule, a server or a model.
func TestAccountRulesMergeIntoTheOperatorsConfig(t *testing.T) {
	ours, err := RenderAccount("agent/permissions.json.tmpl", layouttest.Layout())
	if err != nil {
		t.Fatal(err)
	}
	existing := []byte(`{
	  "model": "anthropic/claude-opus-4",
	  "mcp": {"theirs": {"type": "local", "command": ["their-server"]}},
	  "permission": {"bash": {"*": "ask"}, "read": {"*": "allow", "src/*.key": "allow"}}
	}`)
	merged, err := MergeJSON(existing, ours, nil)
	if err != nil {
		t.Fatal(err)
	}
	got := decode(t, merged)
	if got["model"] != "anthropic/claude-opus-4" {
		t.Errorf("the operator's model was lost: %s", merged)
	}
	permission, ok := got["permission"].(map[string]any)
	if !ok {
		t.Fatalf("permission = %#v, want an object: %s", got["permission"], merged)
	}
	if _, kept := permission["bash"]; !kept {
		t.Errorf("the operator's bash rules were lost: %s", merged)
	}
	read, ok := permission["read"].(map[string]any)
	if !ok {
		t.Fatalf("permission.read = %#v, want an object: %s", permission["read"], merged)
	}
	// Their catch-all survives, and faramir writes none of its own.
	if read["*"] != "allow" {
		t.Errorf("the operator's catch-all was lost: %s", merged)
	}
	// This install's own directory, which is what faramir writes rules for.
	if read["/var/log/faramir/*"] != "deny" {
		t.Errorf("faramir's rules were not added: %s", merged)
	}
	// faramir's wins on a shared pattern; the rest is carried through.
	if read["src/*.key"] != "allow" {
		t.Errorf("an unrelated rule of the operator's was changed: %s", merged)
	}
}

// Detection is what auto acts on, so this covers the finding rather than the
// deciding. A marker is the agent's own configuration rather than anything
// faramir wrote: an opencode project has its directory long before the plugin
// file.
func TestDetectionFindsAnAgentsOwnConfiguration(t *testing.T) {
	for _, tc := range []struct {
		name    string
		markers []string
		want    []string
	}{
		{"an empty tree", nil, nil},
		{"a directory", []string{".claude/"}, []string{"claude"}},
		{"a config file", []string{"opencode.json"}, []string{"opencode"}},
		{"both, sorted", []string{"opencode.json", ".kilo/"}, []string{"kilocode", "opencode"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			for _, marker := range tc.markers {
				var err error
				if name, isDir := strings.CutSuffix(marker, "/"); isDir {
					err = os.Mkdir(filepath.Join(dir, name), 0o700)
				} else {
					err = os.WriteFile(filepath.Join(dir, marker), []byte("{}\n"), 0o644)
				}
				if err != nil {
					t.Fatal(err)
				}
			}
			got := Detected(dir, "")
			if strings.Join(got, ",") != strings.Join(tc.want, ",") {
				t.Errorf("detectedAgents = %v, want %v", got, tc.want)
			}
		})
	}
}

// Every account-wide rule file is merged into what is already there, which is
// what the drift check rests on: it asks whether a file still carries what this
// version writes, and one faramir owned outright would be compared against its
// own contents.
func TestEveryAccountRuleFileIsMerged(t *testing.T) {
	seen := 0
	for _, name := range Known() {
		for _, file := range Targets[name].AccountFiles {
			// A file carrying no rules is not read by the drift check at all, so
			// whether it is merged is not that check's business. faramir's own
			// plugin is one: it is replaced wholesale, replacing it being the
			// update.
			if file.NoRules {
				continue
			}
			seen++
			if !file.Merge {
				t.Errorf("%s writes %s whole, and reportRuleDrift reads every account "+
					"rule file as one faramir merged into: it needs a skip for this one",
					name, file.Path)
			}
		}
	}
	if seen == 0 {
		t.Error("no agent writes account-wide rules, so this asserts nothing")
	}
}

// An agent that keeps nothing beside a project is found from its home, or auto
// could only ever enrol it where it was already enrolled.
func TestAutoFindsATreelessAgentFromTheHome(t *testing.T) {
	tree, home := t.TempDir(), t.TempDir()
	if got := Detected(tree, home); slices.Contains(got, "codex") {
		t.Errorf("codex found with no evidence anywhere: %v", got)
	}
	if err := os.Mkdir(filepath.Join(home, ".codex"), 0o700); err != nil {
		t.Fatal(err)
	}
	if got := Detected(tree, home); !slices.Contains(got, "codex") {
		t.Errorf("codex not found from the home, so auto can never enrol it a "+
			"first time: %v", got)
	}
	// Without a home to consult it is named rather than guessed at.
	if got := Detected(tree, ""); slices.Contains(got, "codex") {
		t.Errorf("codex found with no home given: %v", got)
	}
	// The enrolment record asks a different question: what this tree carries.
	// The home must not answer it, or a tree would keep an agent it never had.
	if got := detect(ScopeTree, tree); slices.Contains(got, "codex") {
		t.Errorf("the tree reports codex it does not carry: %v", got)
	}
}
