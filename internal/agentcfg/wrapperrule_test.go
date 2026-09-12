package agentcfg

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// The rules an agent enforces itself must not refuse the rewrite the guard
// emits. Claude Code scores a Bash `source <path>` as a read of that path and
// answers it from the deny list before a hook runs, so a Read rule covering the
// wrapper refuses every Bash call in an enrolled tree, the guard's own
// exemption being on the far side of a refusal that already happened.
//
// Asserted against both files Claude Code reads. The account settings and an
// enrolled tree's settings.local carry the rendered set each, and the agent
// enforces the union, so a check that asked only one of them would pass while
// an enrolled tree stayed refused.
func TestNoRenderedRuleRefusesReadingTheWrapper(t *testing.T) {
	layout := layouttest.Layout()
	layout.Blocked = []config.BlockedPath{{Path: "/srv/luks.key"}}
	wrapper := layout.WrapScript()

	for _, asset := range []string{
		"agent/claude/settings.json",
		"agent/claude/settings.local.json.tmpl",
	} {
		data, err := RenderData(asset, PluginData{BinDir: hostlayout.DefaultBinDir, Layout: layout})
		if err != nil {
			t.Fatal(err)
		}
		var file struct {
			Permissions struct {
				Deny []string `json:"deny"`
			} `json:"permissions"`
		}
		if err := json.Unmarshal(data, &file); err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		if len(file.Permissions.Deny) == 0 {
			t.Fatalf("%s rendered no deny rules", asset)
		}
		for _, rule := range file.Permissions.Deny {
			if verb, pattern, ok := strings.Cut(rule, "("); ok && verb == "Read" &&
				covers(strings.TrimSuffix(pattern, ")"), wrapper) {
				t.Errorf("%s: %q refuses reading %s, which is every Bash call in an "+
					"enrolled tree", asset, rule, wrapper)
			}
		}
	}
}

// What the Read rule gave up is not left ungiven: the directory is still
// refused to a writer, which is what it needed. Rewriting the wrapper turns
// redaction into whatever the replacement does, and replacing the pattern file
// beside it decides what the guard refuses.
func TestTheWrapperDirectoryIsStillRefusedToAWriter(t *testing.T) {
	layout := layouttest.Layout()
	want := "Edit(//" + strings.TrimPrefix(layout.LibexecDir, "/") + ")"
	if rules := claudeRules(layout); !slices.Contains(rules, want) {
		t.Errorf("the rules do not carry %q, so nothing refuses writing the wrapper", want)
	}
}

// covers reports whether a rendered Claude Code pattern refuses path: the
// pattern names it, or names a directory above it. Both are anchored at the
// filesystem root, the rendered patterns carrying the "//" that does it.
func covers(pattern, path string) bool {
	pattern = "/" + strings.TrimPrefix(strings.TrimPrefix(pattern, "//"), "/")
	return pattern == path || strings.HasPrefix(path, strings.TrimSuffix(pattern, "/")+"/")
}
