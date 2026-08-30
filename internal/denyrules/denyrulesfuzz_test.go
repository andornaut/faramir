package denyrules

import (
	"regexp"
	"strings"
	"testing"
	"unicode/utf8"
)

// A path becomes a rule, and the rule is what the agent's own hook matches
// against a command line. Two things have to hold for any path an operator can
// name: the rule refuses every spelling a shell expands to that file, and it
// leaves alone a name that merely begins with it.
func FuzzARuleRefusesEverySpellingAndNothingWider(f *testing.F) {
	f.Add("/home/op", ".private/token")
	f.Add("/home/op", "a b/c")
	f.Add("/home/op", "x.y(z)")
	f.Add("/root", ".ssh/id_ed25519")

	f.Fuzz(func(t *testing.T, home, rest string) {
		if !strings.HasPrefix(home, "/") || strings.Contains(home, "\n") || strings.HasSuffix(home, "/") {
			t.Skip()
		}
		if rest == "" || strings.ContainsAny(rest, "\n\r") || strings.HasPrefix(rest, "/") {
			t.Skip()
		}
		if !utf8.ValidString(home) || !utf8.ValidString(rest) {
			t.Skip()
		}
		path := home + "/" + rest
		// DirUnder, which is what every caller uses: it is what puts the end
		// bound on a subject, and a subject without one matches a sibling whose
		// name merely begins the same way.
		rules := Naming([]string{DirUnder(home, path)})
		if len(rules) == 0 {
			t.Fatalf("a path produced no rules: %q", path)
		}
		var read *regexp.Regexp
		for i, rule := range rules {
			re, err := regexp.Compile(rule)
			if err != nil {
				t.Fatalf("rule %d for %q does not compile: %v", i, path, err)
			}
			if i == 0 {
				read = re
			}
		}
		for _, spelling := range []string{path, "~/" + rest, "$HOME/" + rest, "${HOME}/" + rest} {
			if !read.MatchString("cat " + spelling) {
				t.Fatalf("the read rule for %q does not refuse `cat %s`", path, spelling)
			}
		}
		// A sibling whose name merely begins with this one is somebody else's
		// file, and a rule that took it would refuse work nobody asked it to.
		wider := path + "-sibling"
		if read.MatchString("cat "+wider) && !strings.HasSuffix(path, "-sibling") {
			t.Fatalf("the rule for %q also refuses `cat %s`", path, wider)
		}
	})
}
