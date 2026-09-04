package install

import (
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/agentcfg"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// The point of the exercise: one list, and every agent that has a rule file
// for it rendering the same paths. Each rendering is checked
// for a token from every entry, so an agent whose spelling drops one fails here
// rather than in somebody's home directory.
//
// A token rather than the whole pattern, the spellings differing by design;
// what must not differ is which paths appear at all.
func TestEveryAgentsRulesCoverEveryProtectedPath(t *testing.T) {
	layout := testLayout()
	type rendering struct{ asset, body string }
	rendered := make([]rendering, 0, 3)
	for _, asset := range []string{
		"agent/claude/settings.json",
		"agent/permissions.json.tmpl",
	} {
		body, err := agentcfg.RenderAccount(asset, layout)
		if err != nil {
			t.Fatalf("%s: %v", asset, err)
		}
		rendered = append(rendered, rendering{asset, string(body)})
	}
	// The agents with no rule file of their own are refused these by the guard
	// instead, which reads the same list rendered into the pattern file it
	// matches against. Their coverage is that file's, so it is checked here with
	// the rest rather than being taken on trust.
	patterns, err := agentcfg.RenderDenyPatterns(layout)
	if err != nil {
		t.Fatal(err)
	}
	rendered = append(rendered, rendering{"agent/hooks/deny-patterns.txt", string(patterns)})

	if len(rendered) < 3 {
		t.Fatalf("rendered %d file(s), want the two config assets and the pattern "+
			"file: an agent missing here is one nothing checks", len(rendered))
	}
	for _, r := range rendered {
		// Two of these spellings are regexes, where "." arrives escaped, so the
		// backslashes come out before the search: what is being asserted is that
		// the path is in there at all, not how it had to be written.
		flat := strings.ReplaceAll(r.body, `\`, "")
		for _, dir := range agentcfg.Dirs(layout) {
			if !strings.Contains(flat, dir) {
				t.Errorf("%s does not refuse %s", r.asset, dir)
			}
		}
	}
}

// Read and write take the same paths. A value the agent cannot read is one it
// can still destroy, and an age key replaced is every managed file unreadable
// retroactively, so a list that covers one and not the other is half a rule.
func TestReadAndWriteAreRefusedTheSamePaths(t *testing.T) {
	body, err := agentcfg.RenderAccount("agent/claude/settings.json", testLayout())
	if err != nil {
		t.Fatal(err)
	}
	reads, edits := map[string]bool{}, map[string]bool{}
	for _, m := range regexp.MustCompile(`"(Read|Edit)\((.*?)\)"`).FindAllStringSubmatch(string(body), -1) {
		if m[1] == "Read" {
			reads[m[2]] = true
		} else {
			edits[m[2]] = true
		}
	}
	if len(reads) == 0 {
		t.Fatal("no Read rules were rendered")
	}
	for pattern := range reads {
		if !edits[pattern] {
			t.Errorf("%s is refused on read and permitted on edit", pattern)
		}
	}
	for pattern := range edits {
		if !reads[pattern] {
			t.Errorf("%s is refused on edit and permitted on read", pattern)
		}
	}
}

// An empty directory in the list is a rule that refuses every absolute path.
// Layout is built field by field and a caller filling only what it needs is the
// ordinary way to reach one, so the partial layouts below are the cases.
func TestInstallDirsAreNeverEmpty(t *testing.T) {
	for _, layout := range []hostlayout.Layout{
		{},
		{ConfigDir: "/opt/conf"},
		{LogDir: "/var/log/x"},
		testLayout(),
	} {
		dirs := agentcfg.Dirs(layout)
		if len(dirs) == 0 {
			t.Errorf("installDirs(%+v) yielded nothing, so every rule built from it "+
				"covers no path and the tests over it assert nothing", layout)
		}
		for _, dir := range dirs {
			if strings.TrimSpace(dir) == "" || dir == "/" {
				t.Errorf("installDirs(%+v) yielded %q, which refuses everything", layout, dir)
			}
		}
	}
}

// `faramir init` writes the deny rules into a home, for the agents that enforce
// rules of their own. They hold wherever the agent is working rather than in a
// tree somebody enrolled: an operator's declared paths are the host's, and an
// agent wanders into directories nobody pointed faramir at.
func TestInitWritesTheDenyRulesIntoTheHome(t *testing.T) {
	for _, tc := range []struct {
		agent string
		file  string
		want  string
	}{
		// Two slashes: Claude Code anchors a one-slash pattern at the settings
		// source, so only this spelling names the filesystem root.
		{"claude", ".claude/settings.json", `"Read(//etc/faramir/**)"`},
		{"opencode", ".config/opencode/opencode.json", `"/etc/faramir/*": "deny"`},
		{"kilocode", ".config/kilo/kilo.json", `"/etc/faramir/*": "deny"`},
	} {
		t.Run(tc.agent, func(t *testing.T) {
			target := agentcfg.Targets[tc.agent]
			var file agentcfg.File
			// In a home: the rules an agent enforces itself are account-wide, so
			// they hold in every directory rather than an enrolled one.
			for _, candidate := range target.AccountFiles {
				if candidate.Path == tc.file {
					file = candidate
				}
			}
			if file.Path == "" {
				t.Fatalf("%s writes no %s", tc.agent, tc.file)
			}
			body, err := agentcfg.AssetFor(target, file, "/etc/faramir")
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(body), tc.want) {
				t.Errorf("%s carries no deny rule for this install's own directory:\n%s",
					tc.file, body)
			}
			// This install's own directories with them, which are literal rather
			// than patterns: a store moved by --config-dir is the one refused.
			if !strings.Contains(string(body), "/etc/faramir/secrets") {
				t.Errorf("%s does not refuse this install's secrets directory:\n%s",
					tc.file, body)
			}
		})
	}
}

// A caller that knows where the config is and not what the accounts are called
// still has to be told the daemons' own homes are faramir's. enrol and
// doctor both build a Layout out of the config directory alone, and with these
// dropped `enrol /var/lib/faramir-keeper` was an ordinary enrolment: the
// home goes to the operator at 2770, and the walk regroups the .ssh inside it
// from 0700 to the client group.
func TestInstallDirsNamesTheDaemonHomesWithoutBeingToldTheAccounts(t *testing.T) {
	dirs := agentcfg.Dirs(hostlayout.Layout{ConfigDir: "/etc/faramir"})
	for _, want := range []string{
		"/var/lib/" + hostlayout.DefaultBrokerUser,
		"/var/lib/" + hostlayout.DefaultKeeperUser,
		"/var/lib/" + hostlayout.DefaultExecUser,
	} {
		if !slices.Contains(dirs, want) {
			t.Errorf("installDirs does not name %s: %v", want, dirs)
		}
	}
	// And a name it was given still wins, or renaming an account would protect
	// the directory the install stopped using and not the one it moved to.
	named := agentcfg.Dirs(hostlayout.Layout{ConfigDir: "/etc/faramir", ExecUser: "faramir-runner"})
	if !slices.Contains(named, "/var/lib/faramir-runner") {
		t.Errorf("installDirs ignores a named exec account: %v", named)
	}
}
