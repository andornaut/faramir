package install

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// Claude Code's enrolment is split across two files: the account settings
// carry the deny rules and a deny-only hook, and the tree's settings.local
// carries the same rules beside the hook that routes. The duplication is
// deliberate -- a tree can be enrolled on a host where `init --agent claude`
// never ran -- and it is safe only while both files say the same thing: deny
// rules merge, so a rule written twice refuses the same thing once, and a rule
// written differently refuses two different things with nothing reporting it.
func TestTheAccountAndTreeSettingsCarryTheSameRules(t *testing.T) {
	layout := testLayout()
	layout.Blocked = []config.BlockedPath{{Name: "*.pem"}, {Path: "/srv/luks.key"}}

	type settings struct {
		Permissions struct {
			Deny []string `json:"deny"`
		} `json:"permissions"`
		Hooks struct {
			PreToolUse []struct {
				Hooks []struct {
					Command string `json:"command"`
				} `json:"hooks"`
			} `json:"PreToolUse"`
		} `json:"hooks"`
	}
	read := func(asset string) settings {
		t.Helper()
		data, err := renderData(asset, pluginData{BinDir: DefaultBinDir, Layout: layout})
		if err != nil {
			t.Fatal(err)
		}
		var s settings
		if err := json.Unmarshal(data, &s); err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		return s
	}
	account := read("agent/claude/settings.json")
	tree := read("agent/claude/settings.local.json.tmpl")

	if len(account.Permissions.Deny) == 0 {
		t.Fatal("the account settings rendered no deny rules")
	}
	if got, want := tree.Permissions.Deny, account.Permissions.Deny; !slices.Equal(got, want) {
		t.Errorf("the two files refuse different things:\naccount: %v\ntree:    %v", want, got)
	}

	// And the hooks are the two halves they claim to be: the account's refuses
	// only, the tree's routes.
	hookOf := func(s settings, which string) string {
		t.Helper()
		if len(s.Hooks.PreToolUse) != 1 || len(s.Hooks.PreToolUse[0].Hooks) != 1 {
			t.Fatalf("%s: want exactly one hook, got %+v", which, s.Hooks.PreToolUse)
		}
		return s.Hooks.PreToolUse[0].Hooks[0].Command
	}
	if hook := hookOf(account, "account"); !strings.Contains(hook, "--deny-only") {
		t.Errorf("the account hook routes, which approves Bash on the whole account: %s", hook)
	}
	if hook := hookOf(tree, "tree"); strings.Contains(hook, "--deny-only") {
		t.Errorf("the tree hook is deny-only, so nothing in an enrolled tree is redacted: %s", hook)
	}
}
