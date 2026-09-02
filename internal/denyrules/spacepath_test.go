package denyrules

import (
	"regexp"
	"testing"
)

// A shell writes a space in a path two ways and both reach the same file, so a
// subject that carries only the quoted spelling refuses one and leaves the other
// working. An Electron profile has several such names.
func TestASpaceInAPathIsRefusedInBothSpellings(t *testing.T) {
	const home = "/home/op"
	const path = "/home/op/.config/Code/Local Storage"

	re := regexp.MustCompile(Naming([]string{DirUnder(home, path)})[0])
	for _, command := range []string{
		`cat '/home/op/.config/Code/Local Storage/leveldb'`,
		`cat /home/op/.config/Code/Local\ Storage/leveldb`,
		`cat "~/.config/Code/Local Storage"`,
		`cat ~/.config/Code/Local\ Storage/leveldb`,
		`cat $HOME/.config/Code/Local\ Storage`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it reaches the declared path", command)
		}
	}

	// The bound still holds: a space does not make the subject match a longer
	// name that merely starts the same way.
	for _, command := range []string{
		`cat /home/op/.config/Code/Local\ Storage2/x`,
		`cat '/home/op/.config/Code/Local Storagex'`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and it names a different directory", command)
		}
	}
}

// The same two spellings through the glob rule, which is the other half of what
// a declared path renders. The directory half of a glob quotes a space and the
// name half did not, so a wildcard standing in for part of the name took the
// quoted spelling alone and left the escaped one open.
//
// The app directory here is a name no host declares. A rule for a real one
// carries a relative spelling that matches the name wherever it appears, this
// file included, and a fixture that trips the guard is one nobody can edit.
func TestASpaceInAGlobIsRefusedInBothSpellings(t *testing.T) {
	const home = "/home/op"
	const path = "/home/op/.config/Exampleditor/Local Storage"

	rule := globUnder(home, path)
	if rule == "" {
		t.Fatal("no glob rule for a path under a home, so this asserts nothing")
	}
	re := regexp.MustCompile("(?i)" + rule)
	for _, command := range []string{
		`cat "~/.config/Exampleditor/Local Sto*"`,
		`cat ~/.config/Exampleditor/Local\ Sto*`,
		`cat ~/.config/Exampleditor/Local\ Storag?`,
		`cat ~/.config/Exampleditor/*`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it is a pattern that expands to the "+
				"declared path", command)
		}
	}
	// And the bound: a pattern that cannot expand to this name is left alone.
	for _, command := range []string{
		`cat ~/.config/Exampleditor/User/*.json`,
		`cat ~/.config/Exampleditor/Local\ Storage2*`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and no expansion of it is the declared path", command)
		}
	}
}
