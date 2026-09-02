package denyrules

import (
	"regexp"
	"testing"
)

// A declared file and a declared directory fail differently against a glob: the
// directory's subject is a prefix of what is under it, the file's is a name a
// glob never carries. This is the rule that closes the second case.
func TestAGlobInADeclaredFilesDirectoryIsRefused(t *testing.T) {
	const home = "/home/op"
	subjects := []string{
		DirUnder(home, "/home/op/.ssh/id_rsa"),
		globUnder(home, "/home/op/.ssh/id_rsa"),
	}
	rules := Naming(subjects)
	matches := func(command string) bool {
		for _, rule := range rules {
			if regexp.MustCompile(rule).MatchString(command) {
				return true
			}
		}
		return false
	}

	for _, command := range []string{
		"cat /home/op/.ssh/id_rsa",
		"cat /home/op/.ssh/*",
		"cat /home/op/.ssh/id_r*",
		"cat /home/op/.ssh/id_rs?",
		"cat ~/.ssh/*",
		"cat $HOME/.ssh/*",
		`for f in /home/op/.ssh/*; do cat "$f"; done`,
		"base64 /home/op/.ssh/*",
	} {
		if !matches(command) {
			t.Errorf("%q is allowed, and it reaches the declared key", command)
		}
	}

	// Naming a file in that directory outright is still allowed: the cost of
	// this rule is meant to fall on globs alone.
	for _, command := range []string{
		"cat /home/op/.ssh/known_hosts",
		"cat /home/op/.ssh/config",
		"cat /home/op/.ssh/id_rsa.pub",
		"ls -l /home/op/.ssh",
		// A neighbouring directory whose name merely starts the same way.
		"cat /home/op/.sshrc/*",
	} {
		if matches(command) {
			t.Errorf("%q is refused, and it names no declared file", command)
		}
	}
}

// A home, or anything above one, gets no rule: the parent of a home is /home,
// and a pattern rule there answers for every account on the host.
func TestNoGlobRuleIsWrittenForAHomeOrAbove(t *testing.T) {
	for _, tc := range []struct{ home, path string }{
		{"/home/op", "/home/op"},
		{"/home/op", "/home"},
		{"/home/op", "/"},
		{"", "/etc"},
	} {
		if got := globUnder(tc.home, tc.path); got != "" {
			t.Errorf("globUnder(%q, %q) = %q, want no rule", tc.home, tc.path, got)
		}
	}
}

// A file directly in a home does get one, and it is about that file's name
// rather than about the home: `~/*` could produce .netrc where the shell is set
// to expand a leading dot, and `~/notes*` could not.
func TestAFileInAHomeIsCoveredByItsOwnName(t *testing.T) {
	rules := Naming([]string{globUnder("/home/op", "/home/op/.netrc")})
	matches := func(command string) bool {
		for _, rule := range rules {
			if regexp.MustCompile(rule).MatchString(command) {
				return true
			}
		}
		return false
	}
	for _, command := range []string{"cat /home/op/*", "cat /home/op/.n*", "cat ~/.netr?"} {
		if !matches(command) {
			t.Errorf("%q is allowed, and it could produce the declared file", command)
		}
	}
	for _, command := range []string{"cat /home/op/notes*", "cat /home/op/src/*"} {
		if matches(command) {
			t.Errorf("%q is refused, and it could not produce the declared file", command)
		}
	}
}

// A declared directory already covers a glob under it, so the rule it would
// generate is about its parent and must not be written.
func TestADeclaredDirectoryAlreadyCoversAGlobUnderIt(t *testing.T) {
	const home = "/home/op"
	rules := Naming([]string{DirUnder(home, "/home/op/.gnupg")})
	matched := false
	for _, rule := range rules {
		if regexp.MustCompile(rule).MatchString("cat /home/op/.gnupg/*") {
			matched = true
		}
	}
	if !matched {
		t.Error("a glob under a declared directory is allowed, which it was not before")
	}
}

// The rule ends at the wildcard, so it names one word and cannot run along the
// line into somebody else's pattern.
func TestTheGlobRuleNamesOneWord(t *testing.T) {
	re := regexp.MustCompile(Naming([]string{globUnder("/home/op", "/home/op/.ssh/id_rsa")})[0])
	for _, command := range []string{
		"cat /home/op/notes.md; ls /tmp/*",
		"cat /home/op/.sshrc/*",
		"cat /home/op/.ssh_backup/*",
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and it reaches no declared file", command)
		}
	}
}
