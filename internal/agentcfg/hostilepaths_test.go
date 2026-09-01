package agentcfg

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// hostilePaths are filenames an operator can really create and really link. None
// is rejected by the loader: it checks for "~", a relative path, a path that is
// not in its shortest form, and "/", and a name is otherwise whatever the
// filesystem allowed.
//
// Each is here because it means something to one of the languages a rule is
// written in: JSON, a glob, a regex, or Claude Code's Read(...) rule syntax.
var hostilePaths = map[string]string{
	"a closing paren":     `/home/op/secrets(prod).env`,
	"a double quote":      `/home/op/say "hi".env`,
	"a backslash":         `/home/op/back\slash.env`,
	"a newline":           "/home/op/two\nlines.env",
	"glob metacharacters": `/home/op/*.env`,
	"a bracket class":     `/home/op/[abc].env`,
	"regex quantifiers":   `/home/op/a+b?c.env`,
	"an alternation":      `/home/op/a|b.env`,
	"a brace":             `/home/op/{a,b}.env`,
	"a dollar and caret":  `/home/op/^start$.env`,
	"a tab":               "/home/op/tab\there.env",
}

// layoutWithPath is this install's layout carrying one linked and one refused
// path, which is what every rule renderer reads.
func layoutWithPath(path string) hostlayout.Layout {
	l := testLayout()
	l.Links = []config.Link{{Ref: "hostile", Path: path, Type: "text"}}
	l.Blocked = []config.BlockedPath{{Path: path + ".refused"}}
	return l
}

// Every agent file faramir writes as JSON has to stay parseable whatever the
// path is called. A path that broke the quoting would not fail loudly: the
// agent would read a file it cannot parse, and every rule in it -- including the
// ones protecting everything else -- would be gone.
func TestHostilePathsKeepTheAgentFilesParseable(t *testing.T) {
	// One shape of data now: an account file renders against the same pluginData
	// a tree's does, the layout inside it, so that one which is a program can
	// name the binary it execs.
	perProject := []string{"agent/claude/settings.local.json.tmpl"}
	// Where the rules live now: a home. Every agent's, so a path that breaks one
	// spelling is caught whichever agent reads it.
	accountWide := []string{
		"agent/permissions.json.tmpl",
		"agent/claude/settings.json",
		"agent/agy/settings.json",
	}
	for name, path := range hostilePaths {
		layout := layoutWithPath(path)
		type job struct {
			asset string
			data  any
		}
		jobs := make([]job, 0, len(perProject)+len(accountWide))
		for _, a := range perProject {
			jobs = append(jobs, job{a, PluginData{
				BinDir: "/usr/local/bin", Agent: "claude", Path: "/srv/tree", Layout: layout,
			}})
		}
		for _, a := range accountWide {
			jobs = append(jobs, job{a, PluginData{BinDir: hostlayout.DefaultBinDir, Layout: layout}})
		}
		for _, j := range jobs {
			asset := j.asset
			body, err := RenderData(asset, j.data)
			if err != nil {
				t.Errorf("%s: %s did not render: %v", name, asset, err)
				continue
			}
			var parsed any
			if err := json.Unmarshal(body, &parsed); err != nil {
				t.Errorf("%s (%q): %s is not valid JSON: %v\n%s",
					name, path, asset, err, body)
			}
		}
	}
}

// And the path has to survive into the rule intact. Claude Code's rules wrap it
// as Read(<path>), so a closing paren in a filename can end the rule early: what
// is left refuses some other path, and the file it was written for is not
// refused at all.
func TestHostilePathsSurviveIntoTheClaudeRules(t *testing.T) {
	for name, path := range hostilePaths {
		rules := claudeRules(layoutWithPath(path))
		want := "Read(" + path + ")"
		if !slices.Contains(rules, want) {
			t.Errorf("%s (%q): no rule reads exactly %q.\ngot rules mentioning it: %v",
				name, path, want, mentioning(rules, "secrets"))
		}
	}
}

func mentioning(rules []string, needle string) []string {
	var out []string
	for _, r := range rules {
		if strings.Contains(r, needle) {
			out = append(out, r)
		}
	}
	return out
}
