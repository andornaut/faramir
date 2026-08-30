package denyrules

import (
	"regexp"
	"testing"
)

// A command that changes directory first names the file with no prefix at all,
// and the four prefixed spellings all miss it. What the tail costs is a file of
// the same name in another tree, which is refused with it.
func TestARelativeSpellingIsRefused(t *testing.T) {
	const home = "/home/op"
	const path = "/home/op/.ssh/id_rsa"

	re := regexp.MustCompile(Naming([]string{DirUnder(home, path)})[0])
	for _, command := range []string{
		`cd $HOME && cat .ssh/id_rsa`,
		`cd ~ && ls -ld .ssh/id_rsa`,
		`cat /home/op/.ssh/id_rsa`,
		`cat ~/.ssh/id_rsa`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it reaches the declared path", command)
		}
	}

	// Both bounds still hold. A tail is not a prefix of a longer name, and it is
	// not the end of a longer one either.
	for _, command := range []string{
		`cat .ssh/id_rsa.pub`,
		`cat .ssh/id_rsafoo`,
		`cat backup.ssh/id_rsa`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and it names a different file", command)
		}
	}

	// The home itself keeps its own spellings and gains no empty tail: a rule
	// for the home would otherwise match every command.
	re = regexp.MustCompile(Naming([]string{DirUnder(home, home)})[0])
	if re.MatchString(`echo hello`) {
		t.Error("a rule for the home matches a command naming no path at all")
	}
}

// A tail that is one ordinary word is not a path, and pathStart bounds a match
// inside a word rather than a match on a whole one. Without the boundary a rule
// for one directory refuses every command that happens to use the word.
func TestAWordIsNotARelativeSpelling(t *testing.T) {
	re := regexp.MustCompile(Naming([]string{DirUnder("/home/op", "/home/op/secrets")})[0])
	for _, command := range []string{
		`echo "no secrets here"`,
		`git commit -m "drop the secrets"`,
		`rg -n TODO /var/www/secrets`,
		`KEY=secrets make`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and it names nothing under the home", command)
		}
	}
	// The four prefixed spellings are what covers it instead.
	for _, command := range []string{
		`cat /home/op/secrets/db.key`,
		`cat ~/secrets/db.key`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it reaches the declared path", command)
		}
	}

	// A name opening on a dot is a path rather than a word, so it keeps its tail.
	re = regexp.MustCompile(Naming([]string{DirUnder("/home/op", "/home/op/.npmrc")})[0])
	if !re.MatchString(`cd $HOME && cat .npmrc`) {
		t.Error("a dotfile directly under the home lost its relative spelling")
	}
	if re.MatchString(`cat package.npmrc`) {
		t.Error("the tail matched the end of a longer name")
	}
}
