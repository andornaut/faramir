package denyrules

import (
	"regexp"
	"slices"
	"testing"
)

// A path rule is a literal, and the tilde is how a person and a model both name
// a file under a home. Without the other spellings `cat ~/.private/x` reaches a
// file that `cat /home/op/.private/x` is refused, which is the accident this
// list exists to catch rather than the evasion it does not claim to stop.
func TestAPathUnderAHomeIsRefusedInEverySpellingAShellExpands(t *testing.T) {
	const home = "/home/op"
	subject := DirUnder(home, home+"/.private")
	re := regexp.MustCompile("(?i)" + ReadCommands + ArgSpan + `(` + subject + `)`)
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
	re := regexp.MustCompile("(?i)" + ReadCommands + ArgSpan + `(` + subject + `)`)
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

// rules is the five rules as the guard compiles them, so a test asks the same
// question the guard does rather than a version of it. Named rather than
// positional: a case says which rule should hold it.
type rules struct {
	read, input, write, redirect, assign *regexp.Regexp
}

// all is every rule, for a case that must match none of them.
func (r rules) all() []*regexp.Regexp {
	return []*regexp.Regexp{r.read, r.input, r.write, r.redirect, r.assign}
}

func compiled(t *testing.T, subjects ...string) rules {
	t.Helper()
	got := For(subjects)
	if len(got) != 5 {
		t.Fatalf("For returned %d rules, want the read, input, write, redirect and "+
			"binding five", len(got))
	}
	compile := func(pattern string) *regexp.Regexp {
		return regexp.MustCompile("(?i)" + pattern)
	}
	return rules{compile(got[0]), compile(got[1]), compile(got[2]), compile(got[3]),
		compile(got[4])}
}

// The five rules refuse the five ways a command line reaches a subject. Each
// case names which rule should hold it, so a rule that stops matching is a
// failure here rather than a gap the other three happen to cover.
func TestTheFiveRulesRefuseEveryWayALineReachesASubject(t *testing.T) {
	re := compiled(t, Dir("/etc/faramir"))
	for _, c := range []struct {
		rule *regexp.Regexp
		name string
		cmd  string
	}{
		{re.read, "read", "cat /etc/faramir/age.key"},
		{re.read, "read", "head -c 32 /etc/faramir/age.key"},
		{re.read, "read", "cat < /etc/faramir/age.key"},
		// The input rule reaches what the reader vocabulary cannot: these name
		// no reader and print the file anyway.
		{re.input, "input", "while read l; do echo $l; done < /etc/faramir/age.key"},
		{re.input, "input", "mapfile -t key < /etc/faramir/age.key"},
		{re.input, "input", "md5sum </etc/faramir/age.key"},
		{re.read, "read", "sudo cat /etc/faramir/age.key"},
		{re.read, "read", "true; cat /etc/faramir/age.key"},
		{re.read, "read", `python3 -c "open('/etc/faramir/age.key')"`},
		{re.read, "read", "cat '/etc/faramir/age.key'"},
		// The directory itself, not only a file under it.
		{re.read, "read", "tar cf - /etc/faramir"},
		{re.write, "write", "rm -rf /etc/faramir"},
		{re.write, "write", "chmod 0644 /etc/faramir/age.key"},
		{re.write, "write", "echo hi | tee /etc/faramir/age.key"},
		{re.redirect, "redirect", "echo x > /etc/faramir/age.key"},
		{re.redirect, "redirect", "echo x >> /etc/faramir/age.key"},
		{re.redirect, "redirect", "echo x 2>/etc/faramir/age.key"},
		// The four rules above read left to right, so a command has to appear
		// before the path it reaches. An assignment names the path with no
		// command near it, and the reader that follows names only the variable.
		{re.assign, "assign", "p=/etc/faramir/age.key; cat $p"},
		{re.assign, "assign", "export KEY=/etc/faramir/age.key"},
		{re.assign, "assign", `p="/etc/faramir/age.key"`},
		{re.assign, "assign", `p='/etc/faramir/age.key'`},
		// A path quoted because it holds a space. The bare form ends at that
		// space, so the quoted form is matched to the closing quote instead.
		{re.assign, "assign", `p="/etc/faramir/my key.txt"`},
		{re.assign, "assign", `p='/etc/faramir/my key.txt'`},
		{re.assign, "assign", `for d in "/etc/faramir"; do cat $d/age.key; done`},
		{re.assign, "assign", `for d in '/etc/faramir'; do cat $d/age.key; done`},
		{re.assign, "assign", "for d in /etc/faramir; do cat $d/age.key; done"},
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
	re := compiled(t, Dir("/etc/faramir"))
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
		// A heredoc is not an input redirect, and neither is a process
		// substitution or a "<" that is part of what a command prints.
		"cat <<'EOF'\nnothing here\nEOF",
		"diff <(echo a) <(echo b)",
		"echo 'a < b is true of /etc/faramirx'",
		// A sibling in an assignment is still a sibling.
		"p=/etc/faramirx/notes.md",
		// A flag that ends in "=" is not an assignment. A word boundary falls
		// after a hyphen, so the assignment rule read "file=" out of the middle
		// of "--key-file=" and refused the spelling most tooling writes for a
		// path a command is meant to be handed.
		"cryptsetup luksOpen /dev/sdb x --key-file=/etc/faramir/age.key",
		"restic --password-file=/etc/faramir/age.key snapshots",
		// The value ends where the shell ends it, so a path further along the
		// line is not read as this assignment's.
		"greeting=hello /etc/faramirx",
		// A quoted value that is prose rather than a path: the quoted form is
		// taken only where it opens with a path character, or a blocked name
		// that is an ordinary word would refuse a sentence for saying it.
		`title="my faramir talk"`,
		`msg='the faramir docs are here'`,
		// And a loop over a neighbouring directory is left alone too.
		"for d in /etc/faramirx; do cat $d/notes.md; done",
	} {
		for _, rule := range re.all() {
			if rule.MatchString(cmd) {
				t.Errorf("%q is refused, and it does not reach the subject", cmd)
			}
		}
	}
}

// A rule reaches a path in the command it started in and no further. What ends
// a command is Segments, not the rule, so the two are asserted together: a rule
// on its own spans whatever it is given, and giving it a whole line is the
// mistake this pairing exists to prevent.
//
// Without it, any reader anywhere on a line is read as reaching a path named
// later on it, and the refusal names a rule the operator cannot connect to what
// they ran.
func TestAReaderReachesAPathOnlyInTheCommandItSharesWithIt(t *testing.T) {
	read := compiled(t, Dir("/etc/faramir")).read
	reaches := func(line string) bool {
		return slices.ContainsFunc(Segments(line), read.MatchString)
	}
	for _, line := range []string{
		"cat notes.txt | grep /etc/faramir/age.key",
		"head -20 README.md; echo /etc/faramir",
		`head -20 "README.md"; echo "/etc/faramir"`,
		`sed 's/a/b/' x | grep '/etc/faramir/age.key'`,
	} {
		if reaches(line) {
			t.Errorf("%q: a reader is read as reaching a path in another command", line)
		}
	}
	// And the reach holds on the side the reader is on, and inside one command
	// however the separator characters appear in it.
	for _, line := range []string{
		"cat /etc/faramir/age.key | wc -l",
		"echo hi | cat /etc/faramir/age.key",
		"head -20 README.md; cat /etc/faramir/age.key",
		// A pipe inside an argument is an argument. The rule spans it because
		// Segments did not treat it as the end of anything.
		`cat 'a|b' /etc/faramir/age.key`,
		`python3 -c 'import os; print(open("/etc/faramir/age.key").read())'`,
		"cat 2>&1 /etc/faramir/age.key",
	} {
		if !reaches(line) {
			t.Errorf("%q: the reader reaches the path in its own command", line)
		}
	}
}

// A here-string passes text rather than the file, and the input rule matches it
// anyway. Pinned rather than fixed: the rules match the command string and not
// what it would do, which is the limit the whole list has, and the refusal
// names the rule so an operator who meant the text can write it another way.
// RE2 has no lookbehind, and "\S*" steps over the extra "<" regardless.
func TestAHereStringIsRefusedLikeARedirect(t *testing.T) {
	input := compiled(t, Dir("/etc/faramir")).input
	if !input.MatchString(`grep x <<<'/etc/faramir/age.key'`) {
		t.Error("a here-string naming a protected path is allowed; if this was " +
			"fixed deliberately, say so here rather than deleting the case")
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

// The name a tool has where it is not the default one. Ubuntu 26.04 ships
// uutils as `cat` and the GNU build as `gnucat`, for 104 programs, 18 of them
// in this vocabulary. A word boundary does not fall inside `gnucat`, so every
// one of those walked past these rules on that release.
func TestTheGnuPrefixedNamesAreTheSameTools(t *testing.T) {
	re := compiled(t, Dir("/etc/faramir"))
	refused := func(cmd string) bool {
		for _, rule := range re.all() {
			if rule.MatchString(cmd) {
				return true
			}
		}
		return false
	}
	for _, cmd := range []string{
		"gnucat /etc/faramir/age.key",
		"gnuhead -c1 /etc/faramir/secrets/app.sops.yml",
		"gnubase64 /etc/faramir/age.key",
		"gnucp /etc/faramir/age.key /tmp/k",
		"gnurm /etc/faramir/config.toml",
		"gnutee /etc/faramir/config.toml",
		// And the ordinary names, which the prefix must not have displaced.
		"cat /etc/faramir/age.key",
		"rm /etc/faramir/config.toml",
	} {
		if !refused(cmd) {
			t.Errorf("%q is allowed: the prefixed name is the same tool", cmd)
		}
	}
	// Only that prefix, and only where the rest is a word this list already
	// knows. A rule fires where one of these meets a protected path, so a name
	// nobody installed refuses nothing; a name that merely starts with one of
	// these words was never matched and still is not.
	for _, cmd := range []string{
		"gnuplot /etc/faramir/notes.txt",
		"concat /etc/faramir/notes.txt",
		"category /etc/faramir/notes.txt",
		"uucat /etc/faramir/age.key",
	} {
		if refused(cmd) {
			t.Errorf("%q is refused, and it names no tool in the vocabulary", cmd)
		}
	}
}
