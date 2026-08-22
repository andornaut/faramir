package install

import (
	"testing"

	"github.com/andornaut/faramir/internal/config"
)

// The point of one protected set: a declared entry covers both entry points.
// Before this, `block add` rendered a rule into every agent's file tools and
// said nothing to the command guard, so `cat` on the very path an operator had
// just refused was allowed, and nothing said so.
func TestADeclaredEntryReachesTheCommandRules(t *testing.T) {
	layout := Layout{
		ConfigDir:  "/etc/faramir",
		LogDir:     "/var/log/faramir",
		LibexecDir: "/usr/local/libexec/faramir",
		Blocked: []config.BlockedPath{
			{Path: "/etc/luks/volume.key"},
			{Name: "*.pem"},
			{Name: "id_rsa"},
			{Name: ".storage/auth"},
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
		{"base64 certs/server.pem", true, "a declared suffix"},
		{"cat ~/.ssh/id_rsa", true, "a declared name"},
		{"cat /config/.storage/auth", true, "a declared name inside a directory"},
		{"cat /home/op/.npmrc", true, "a linked file, which is refused like a declared one"},
		{"cat /etc/faramir/age.key", true, "this install's own, from the layout"},

		{"cat certs/server.crt", false, "a neighbouring file the suffix does not name"},
		{"cat ~/.ssh/id_rsa.pub", false, "the public half is not the key"},
		{"cat /config/.storage/other", false, "a sibling of the declared name"},
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
// others: the set is never empty, so the four rules are always rendered, and
// an empty alternation matching every command is the failure to avoid.
func TestAnInstallThatDeclaresNothingRefusesItsOwn(t *testing.T) {
	rules := commandRules(Layout{ConfigDir: "/etc/faramir"})
	if len(rules) != 4 {
		t.Fatalf("rendered %d rules, want four: %v", len(rules), rules)
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
		Blocked:   []config.BlockedPath{{Name: ".ssh/"}},
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
