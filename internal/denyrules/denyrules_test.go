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
