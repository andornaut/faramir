package denyrules

import (
	"regexp"
	"testing"
)

// A path rule is a literal, and the tilde is how a person and a model both name
// a file under a home. Without the other spellings `cat ~/.private/x` reaches a
// file that `cat /home/op/.private/x` is refused, which is the accident this
// list exists to catch rather than the evasion it does not claim to stop.
func TestAPathUnderAHomeIsRefusedInEverySpellingAShellExpands(t *testing.T) {
	const home = "/home/op"
	subject := DirUnder(home, home+"/.private")
	re := regexp.MustCompile("(?i)" + ReadCommands + `[^|]*(` + subject + `)`)
	for _, cmd := range []string{
		"cat /home/op/.private/x",
		"cat ~/.private/x",
		"cat $HOME/.private/x",
		"cat ${HOME}/.private/x",
	} {
		if !re.MatchString(cmd) {
			t.Errorf("%q is allowed, and it names the refused file", cmd)
		}
	}
}

// And the bound still holds: a sibling that merely starts the same way, and a
// file under the home that nothing declared, are both left alone.
func TestTheHomeSpellingsDoNotWiden(t *testing.T) {
	const home = "/home/op"
	subject := DirUnder(home, home+"/.private")
	re := regexp.MustCompile("(?i)" + ReadCommands + `[^|]*(` + subject + `)`)
	for _, cmd := range []string{
		"cat ~/.privateer/x",
		"cat /home/op/.private-notes.md",
		"cat ~/notes.md",
		"cat /etc/hostname",
	} {
		if re.MatchString(cmd) {
			t.Errorf("%q is refused by a rule about a neighbouring path", cmd)
		}
	}
}

// A path outside every home keeps the one spelling it has, so the alternation
// is not carried where nothing expands to it.
func TestAPathOutsideAHomeGetsNoExtraSpellings(t *testing.T) {
	if got, want := DirUnder("/home/op", "/etc/faramir"), Dir("/etc/faramir"); got != want {
		t.Errorf("DirUnder = %q, want the plain form %q", got, want)
	}
	if got, want := DirUnder("", "/etc/faramir"), Dir("/etc/faramir"); got != want {
		t.Errorf("with no home DirUnder = %q, want %q", got, want)
	}
	// The home itself is not a subject that gets a bare "~": that would be every
	// file the agent owns.
	if got, want := DirUnder("/home/op", "/home/op"), Dir("/home/op"); got != want {
		t.Errorf("the home itself = %q, want %q", got, want)
	}
}

// compiled is the three rules as the guard compiles them, so a test asks the
// same question the guard does rather than a version of it.
func compiled(t *testing.T, subjects ...string) (read, write, redirect *regexp.Regexp) {
	t.Helper()
	rules := For(subjects)
	if len(rules) != 3 {
		t.Fatalf("For returned %d rules, want the read, write and redirect three", len(rules))
	}
	return regexp.MustCompile("(?i)" + rules[0]),
		regexp.MustCompile("(?i)" + rules[1]),
		regexp.MustCompile("(?i)" + rules[2])
}

// The three rules refuse the three ways a command line reaches a subject. Each
// case names which rule should hold it, so a rule that stops matching is a
// failure here rather than a gap the other two happen to cover.
func TestTheThreeRulesRefuseReadingWritingAndRedirectingOverASubject(t *testing.T) {
	read, write, redirect := compiled(t, Dir("/etc/faramir"))
	for _, c := range []struct {
		rule *regexp.Regexp
		name string
		cmd  string
	}{
		{read, "read", "cat /etc/faramir/age.key"},
		{read, "read", "head -c 32 /etc/faramir/age.key"},
		{read, "read", "cat < /etc/faramir/age.key"},
		{read, "read", "sudo cat /etc/faramir/age.key"},
		{read, "read", "true; cat /etc/faramir/age.key"},
		{read, "read", `python3 -c "open('/etc/faramir/age.key')"`},
		{read, "read", "cat '/etc/faramir/age.key'"},
		// The directory itself, not only a file under it.
		{read, "read", "tar cf - /etc/faramir"},
		{write, "write", "rm -rf /etc/faramir"},
		{write, "write", "chmod 0644 /etc/faramir/age.key"},
		{write, "write", "echo hi | tee /etc/faramir/age.key"},
		{redirect, "redirect", "echo x > /etc/faramir/age.key"},
		{redirect, "redirect", "echo x >> /etc/faramir/age.key"},
		{redirect, "redirect", "echo x 2>/etc/faramir/age.key"},
	} {
		if !c.rule.MatchString(c.cmd) {
			t.Errorf("the %s rule allows %q", c.name, c.cmd)
		}
	}
}

// What the rules leave alone. A command that names a protected path without
// reaching it, and a path that merely begins the same way, are both allowed:
// the vocabulary is a list of what reads and what writes, not every command
// that could be typed near one.
func TestTheRulesLeaveAloneWhatDoesNotReachTheSubject(t *testing.T) {
	read, write, redirect := compiled(t, Dir("/etc/faramir"))
	for _, cmd := range []string{
		// "grep" is in neither vocabulary, so naming a path in a search stands.
		"grep secret /etc/faramir/config.toml",
		"ls /etc/faramir",
		// PathEnd bounds the subject, so a sibling is not caught by it.
		"cat /etc/faramirx",
		"cat /opt/faramir-notes.md",
		// The command names are case-sensitive inside a case-insensitive rule:
		// "CAT" is not a command on this system, and the paths still are not.
		"CAT /etc/faramir/age.key",
	} {
		for _, re := range []*regexp.Regexp{read, write, redirect} {
			if re.MatchString(cmd) {
				t.Errorf("%q is refused, and it does not reach the subject", cmd)
			}
		}
	}
}

// A pipe ends a rule's reach. Without that, any reader anywhere on a line would
// be read as reaching a path named later on it, and the refusal would name a
// rule the operator cannot connect to what they ran.
func TestAReaderOnTheOtherSideOfAPipeIsNotReadAsReachingTheSubject(t *testing.T) {
	read, _, _ := compiled(t, Dir("/etc/faramir"))
	if read.MatchString("cat notes.txt | grep /etc/faramir/age.key") {
		t.Error("a reader before a pipe is read as reaching a path after it")
	}
	// And the reach still holds on the side the reader is on.
	if !read.MatchString("cat /etc/faramir/age.key | wc -l") {
		t.Error("a reader is allowed to reach the subject when a pipe follows")
	}
	if !read.MatchString("echo hi | cat /etc/faramir/age.key") {
		t.Error("a reader after a pipe is allowed to reach the subject")
	}
}

// No subjects is no rules. An empty alternation matches the empty string, so
// generating one would leave a rule that any reader on any command line matches.
func TestNoSubjectsIsNoRulesRatherThanARuleMatchingEverything(t *testing.T) {
	for _, subjects := range [][]string{nil, {}} {
		if got := For(subjects); got != nil {
			t.Errorf("For(%#v) = %#v, want no rules", subjects, got)
		}
	}
}
