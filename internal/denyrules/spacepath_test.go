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
