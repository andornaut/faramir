package denyrules

import (
	"regexp"
	"testing"
)

// The home and the entry the prefix form exists for: a file whose name carries
// a per-account number, declared by the part of it a config may carry.
const (
	prefixHome  = "/home/op"
	prefixEntry = "/home/op/.local/share/Steam/ssfn*"
	prefixReal  = "/home/op/.local/share/Steam/ssfn682576826927347580"
)

// The name the entry stands for is refused in every spelling a shell writes it,
// which is the whole point of the form: the number is on the host and not in
// the config that refuses it.
func TestAPrefixEntryRefusesTheNameItStandsFor(t *testing.T) {
	re := regexp.MustCompile(Naming([]string{DirUnder(prefixHome, prefixEntry)})[0])
	for _, command := range []string{
		`cat ` + prefixReal,
		`cat ~/.local/share/Steam/ssfn682576826927347580`,
		`cat $HOME/.local/share/Steam/ssfn682576826927347580`,
		`cat ${HOME}/.local/share/Steam/ssfn682576826927347580`,
		`cd $HOME && cat .local/share/Steam/ssfn682576826927347580`,
		// A second account's file, under a name this entry never saw.
		`cat /home/op/.local/share/Steam/ssfn1`,
		// The literal itself, for a file called exactly that: the rest of the
		// name may be empty.
		`cat /home/op/.local/share/Steam/ssfn`,
		// A prefix standing for a directory covers what is under it, the bound
		// after the name being the one a literal entry carries.
		`cat /home/op/.local/share/Steam/ssfnx/inside`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it reaches a name the entry declares", command)
		}
	}
}

// The bound. A prefix opens the end of one component and nothing else, so a
// sibling that does not share it, a shorter name, and the directory's other
// contents are all left alone.
func TestAPrefixEntryLeavesTheRestOfTheDirectoryAlone(t *testing.T) {
	re := regexp.MustCompile(Naming([]string{DirUnder(prefixHome, prefixEntry)})[0])
	for _, command := range []string{
		`cat /home/op/.local/share/Steam/config/libraryfolders.vdf`,
		`cat /home/op/.local/share/Steam/steamapps/appmanifest_570.acf`,
		// Shorter than the literal, so no expansion of the entry is this file.
		`cat /home/op/.local/share/Steam/ssf`,
		// The same name under a directory the entry did not name.
		`cat /home/op/.local/share/Other/ssfn682576826927347580`,
		// A bare word is not a path, and the relative spelling carries the whole
		// tail rather than the last component of it.
		`echo "no ssfn here"`,
		`git commit -m "drop the ssfn handling"`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and it names nothing the entry declares", command)
		}
	}
}

// The glob half, which for a prefix entry cannot constrain the end of the name:
// any pattern whose literal opening is a prefix of the declared one could
// expand to a file that starts with it. A pattern that could not is still left
// alone, and the parent directory still bounds every one of them.
func TestAPrefixEntryRefusesThePatternsThatCouldReachIt(t *testing.T) {
	rule := globUnder(prefixHome, prefixEntry)
	if rule == "" {
		t.Fatal("no glob rule for a prefix entry, so this asserts nothing")
	}
	re := regexp.MustCompile("(?i)" + rule)
	for _, command := range []string{
		`cat /home/op/.local/share/Steam/ssfn*`,
		`cat /home/op/.local/share/Steam/ss*`,
		`cat /home/op/.local/share/Steam/*`,
		`cat ~/.local/share/Steam/ssfn*`,
	} {
		if !re.MatchString(command) {
			t.Errorf("%q is allowed, and it could expand to a declared name", command)
		}
	}
	for _, command := range []string{
		// No expansion of these opens on the declared literal.
		`cat /home/op/.local/share/Steam/config*`,
		`cat /home/op/.local/share/Steam/steamapps/*.acf`,
		// Another directory entirely.
		`cat /home/op/.local/share/Other/*`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and no expansion of it is a declared name", command)
		}
	}
}

// globUnder writes no rule at or above a home, and a prefix entry has to meet
// that bound by the literal it opens on. "/home/o*" is not "/home/op" by the
// element comparison, and its parent is /home, so without the prefix reading it
// rendered a pattern rule over /home -- refusing `cat /home/*` for every account
// on the host, from an entry one character short of this account's own name.
func TestAPrefixOfAHomeGetsNoGlobRule(t *testing.T) {
	for _, entry := range []string{
		"/home/o*",
		"/home/op*",
		"/hom*",
		// The home itself, which the literal reading already declined.
		"/home/op",
		"/home",
	} {
		if rule := globUnder(prefixHome, entry); rule != "" {
			t.Errorf("globUnder(%q, %q) wrote a rule, and it is at or above the home",
				prefixHome, entry)
		}
	}
	// A prefix below the home still gets one: the bound is the home, not the form.
	if globUnder(prefixHome, "/home/op/.ssh/id_*") == "" {
		t.Error("a prefix entry under the home got no glob rule")
	}
}

// A path written in full keeps the rule it had. The prefix form is recognised
// by a trailing "*" and nothing else, so an ordinary entry is untouched by it.
func TestALiteralEntryIsUnchangedByThePrefixForm(t *testing.T) {
	const path = "/home/op/.ssh/id_rsa"
	re := regexp.MustCompile(Naming([]string{DirUnder(prefixHome, path)})[0])
	if !re.MatchString(`cat ~/.ssh/id_rsa`) {
		t.Error("a literal entry stopped matching the file it names")
	}
	for _, command := range []string{
		`cat ~/.ssh/id_rsa.pub`,
		`cat ~/.ssh/id_rsafoo`,
	} {
		if re.MatchString(command) {
			t.Errorf("%q is refused, and a literal entry does not open the name", command)
		}
	}
}

// TrailingPrefix is the one reader of the form, so what it declines is what the
// rest of the package treats as a literal.
func TestTrailingPrefixTakesOnlyTheAcceptedForm(t *testing.T) {
	for _, tc := range []struct {
		path    string
		literal string
		ok      bool
	}{
		{"/home/op/dir/ssfn*", "/home/op/dir/ssfn", true},
		{"/home/op/dir/a*", "/home/op/dir/a", true},
		// No literal character before the wildcard, so the directory is what to
		// name and this is not the accepted form.
		{"/home/op/dir/*", "/home/op/dir/*", false},
		// Not a trailing wildcard at all.
		{"/home/op/dir/ssfn", "/home/op/dir/ssfn", false},
		{"/home/op/dir/*.json", "/home/op/dir/*.json", false},
	} {
		t.Run(tc.path, func(t *testing.T) {
			literal, ok := TrailingPrefix(tc.path)
			if ok != tc.ok || literal != tc.literal {
				t.Errorf("TrailingPrefix(%q) = %q, %v; want %q, %v",
					tc.path, literal, ok, tc.literal, tc.ok)
			}
		})
	}
}
