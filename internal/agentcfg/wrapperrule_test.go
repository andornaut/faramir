package agentcfg

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
	"github.com/andornaut/faramir/internal/layouttest"
)

// No rule an agent enforces itself may cover the wrapper the guard sources.
// Claude Code checks the paths a Bash command names against its deny list
// before it acts on the hook's decision: a Read rule refuses the rewrite, and an
// Edit rule makes it ask, since whether a `source` writes the file it names
// cannot be told from the text. Either is every Bash call in an enrolled tree,
// with the guard's own exemption never reached.
//
// Asserted against both files Claude Code reads, and against every verb. The
// account settings and an enrolled tree's settings.local carry the rendered set
// each, and the agent enforces the union, so a check that asked only one of them
// would pass while an enrolled tree stayed refused.
func TestNoRenderedRuleCoversTheWrapper(t *testing.T) {
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
			if _, pattern, ok := strings.Cut(rule, "("); ok &&
				covers(strings.TrimSuffix(pattern, ")"), wrapper) {
				t.Errorf("%s: %q covers %s, which is every Bash call in an enrolled tree",
					asset, rule, wrapper)
			}
		}
	}
}

// The gap is the renderer's decision, and the doctor is told so through the same
// predicate, which is what keeps a coverage check from reporting it as drift.
func TestTheWrapperDirectoryIsTheOmission(t *testing.T) {
	layout := layouttest.Layout()
	if !OmittedFrom("claude", layout, layout.LibexecDir) {
		t.Errorf("%s is not omitted from Claude Code's rules, so the doctor reports "+
			"the gap claudeRules leaves", layout.LibexecDir)
	}
	for _, path := range Dirs(layout) {
		if path != layout.LibexecDir && OmittedFrom("claude", layout, path) {
			t.Errorf("%s is omitted from Claude Code's rules, and only the wrapper's "+
				"directory should be", path)
		}
	}
	if OmittedFrom("agy", layout, layout.LibexecDir) {
		t.Error("the omission applies to an agent whose rules do not collide with the rewrite")
	}
}

// covers reports whether a rendered Claude Code pattern refuses path: the
// pattern names it, or names a directory above it. Both are anchored at the
// filesystem root, the rendered patterns carrying the "//" that does it.
func covers(pattern, path string) bool {
	pattern = "/" + strings.TrimPrefix(strings.TrimPrefix(pattern, "//"), "/")
	return pattern == path || strings.HasPrefix(path, strings.TrimSuffix(pattern, "/")+"/")
}
