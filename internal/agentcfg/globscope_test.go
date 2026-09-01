package agentcfg

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/hostlayout"
)

// A declared file in a working directory must not refuse every pattern in it.
//
// The glob rule exists so that `cat <dir>/*` cannot reach a declared file the
// way naming it cannot. Matching a prefix of the name and stopping at the
// wildcard made every pattern match on the empty prefix, so one declared .env
// refused `ls *.md` and `git add *` in the same directory: ordinary work, told
// that the path it named is declared.
func TestAPatternThatCannotReachTheFileIsAllowed(t *testing.T) {
	layout := hostlayout.Layout{
		ConfigDir: "/etc/faramir",
		AgentUser: "",
		Blocked:   []config.BlockedPath{{Path: "/home/op/project/.env"}},
	}
	rules := commandRules(layout)

	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		// Could expand to .env, so refused.
		{"cat /home/op/project/*", true, "a bare pattern could produce the name"},
		{"cat /home/op/project/.e*", true, "and so could a prefix of it"},
		{"cat /home/op/project/*env", true, "and a suffix of it"},
		{"cat /home/op/project/.env", true, "the file itself, named outright"},

		// Could not, so allowed.
		{"ls /home/op/project/*.md", false, "no expansion of this produces .env"},
		{"git add /home/op/project/*.go", false, "nor this"},
		{"grep -r x /home/op/project/*.yml", false, "nor this"},
		{"ls /home/op/other/*", false, "and this is another directory"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if denied := matchesAny(t, rules, tc.command); denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
}
