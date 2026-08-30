package install

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The point of one protected set: a declared entry covers both entry points.
// Before this, `block add` rendered a rule into every agent's file tools and
// said nothing to the command guard, so `cat` on the very path an operator had
// just refused was allowed, and nothing said so.
// A glob in the directory that holds a declared file is refused, which naming
// the file itself does not cover: the shell expands the pattern after the guard
// has answered, so the rule has to be about the pattern.
//
// Through commandRules rather than GlobUnder alone, because the rule is only
// worth anything if an install renders it.
func TestAGlobReachingADeclaredFileIsRefused(t *testing.T) {
	layout := Layout{
		ConfigDir: "/etc/faramir",
		AgentUser: "",
		Blocked: []config.BlockedPath{
			{Path: "/home/op/.ssh/id_rsa"},
			{Path: "/home/op/.gnupg"},
		},
	}
	rules := commandRules(layout)

	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		{"cat /home/op/.ssh/*", true, "a glob over the directory holding a declared key"},
		{"cat /home/op/.ssh/id_r*", true, "and a narrower one"},
		{"base64 /home/op/.ssh/*", true, "whatever reader is in front of it"},
		{"cat /home/op/.gnupg/*", true, "a declared directory already covered this"},

		{"cat /home/op/.ssh/known_hosts", false, "a file in that directory that is not declared"},
		{"cat /home/op/.ssh/config", false, "and another"},
		{"ls -l /home/op/.ssh", false, "listing the directory is not reading a file in it"},
		{"cat /home/op/notes/*", false, "a glob nowhere near a declared path"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if denied := matchesAny(t, rules, tc.command); denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
}

func TestADeclaredEntryReachesTheCommandRules(t *testing.T) {
	layout := Layout{
		ConfigDir:  "/etc/faramir",
		LogDir:     "/var/log/faramir",
		LibexecDir: "/usr/local/libexec/faramir",
		Blocked: []config.BlockedPath{
			{Path: "/etc/luks/volume.key"},
			{Path: "/srv/certs/server.pem"},
			{Path: "/home/op/.ssh/id_rsa"},
			{Path: "/home/op/.storage/auth"},
		},
		Links: []config.Link{{Ref: "npm", Path: "/home/op/.npmrc"}},
	}
	rules := commandRules(layout)

	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		{"cat /etc/luks/volume.key", true, "a declared path, read"},
		{"rm /etc/luks/volume.key", true, "a declared path, destroyed"},
		{"echo x > /etc/luks/volume.key", true, "a declared path, written over"},
		{"base64 /srv/certs/server.pem", true, "a declared path, re-encoded"},
		{"cat /home/op/.ssh/id_rsa", true, "a second declared path"},
		{"cat /home/op/.storage/auth", true, "a declared path inside a directory"},
		{"cat /home/op/.npmrc", true, "a linked file, which is refused like a declared one"},
		{"cat /etc/faramir/age.key", true, "this install's own, from the layout"},

		{"cat /srv/certs/server.crt", false, "a neighbour no entry names"},
		{"cat /home/op/.ssh/id_rsa.pub", false, "the public half is not the key"},
		{"cat /home/op/.storage/other", false, "a sibling of the declared path"},
		{"grep -r TODO .", false, "ordinary work"},
		{"cat README.md", false, "and an ordinary read"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			denied := matchesAny(t, rules, tc.command)
			if denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
}

// An install that declares nothing generates rules for its own paths and no
// others: the set is never empty, so the five rules are always rendered, and
// an empty alternation matching every command is the failure to avoid.
func TestAnInstallThatDeclaresNothingRefusesItsOwn(t *testing.T) {
	rules := commandRules(Layout{ConfigDir: "/etc/faramir"})
	if len(rules) != 5 {
		t.Fatalf("rendered %d rules, want five: %v", len(rules), rules)
	}
	if !matchesAny(t, rules, "cat /etc/faramir/age.key") {
		t.Error("this install's own directory is not refused")
	}
	if matchesAny(t, rules, "cat README.md") {
		t.Error("an ordinary read is refused")
	}
}

// A declared directory covers itself as well as what is under it. Matching only
// the form carrying the separator left `rm -rf ~/.ssh` allowed while `rm -rf
// ~/.ssh/` was refused: a rule a keystroke walks around, and a deletion that
// destroys everything the rule was protecting.
func TestADeclaredDirectoryCoversItself(t *testing.T) {
	rules := commandRules(Layout{
		ConfigDir: "/etc/faramir",
		Blocked:   []config.BlockedPath{{Path: "/home/op/.ssh"}},
	})
	for _, tc := range []struct {
		command string
		denied  bool
		why     string
	}{
		{"rm -rf /home/op/.ssh", true, "the directory, named without its separator"},
		{"rm -rf /home/op/.ssh/", true, "and with it"},
		{"cat /home/op/.ssh/id_rsa", true, "and anything under it"},
		{"cat /home/op/.ssh/id_rsa.pub", true, "the public half too: the entry named the directory"},
		{"cat /home/op/.sshrc", false, "a longer name starting the same way"},
		{"rm -rf /home/op/notes.ssh", false, "and one ending the same way"},
	} {
		t.Run(tc.command, func(t *testing.T) {
			if denied := matchesAny(t, rules, tc.command); denied != tc.denied {
				t.Errorf("denied = %v, want %v: %s", denied, tc.denied, tc.why)
			}
		})
	}
}
