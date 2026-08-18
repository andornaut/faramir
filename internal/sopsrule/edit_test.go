package sopsrule

import (
	"slices"
	"strings"
	"testing"
)

// installed is the file `faramir init` writes, down to the indentation and the
// escaped path_regex.  Every edit here is judged against it, because it is the
// shape almost every host carries.
const installed = `# Which files sops encrypts, and to whom.  Any *.sops.yml, wherever it sits.
creation_rules:
  - path_regex: \.sops\.ya?ml$
    key_groups:
      - age:
          - age1keeper
          - age1backup
`

func recipients(t *testing.T, body []byte) []string {
	t.Helper()
	rules, err := Parse(body, "test")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	return Recipients(rules)
}

// An operator who opens the file after an edit should find the one they had.
// The comment and the escaped path_regex are what a re-render loses first, and
// path_regex losing its backslashes is a rule that matches nothing.
func TestAnEditKeepsTheRestOfTheFile(t *testing.T) {
	out, added, err := Add([]byte(installed), "test", "age1third")
	if err != nil || !added {
		t.Fatalf("add: %v (added %v)", err, added)
	}
	for _, want := range []string{
		"# Which files sops encrypts",
		`path_regex: \.sops\.ya?ml$`,
		"age1keeper",
		"age1third",
	} {
		if !strings.Contains(string(out), want) {
			t.Errorf("the edit lost %q:\n%s", want, out)
		}
	}
}

// Appended rather than sorted: the keeper's own key leads the list on every host
// the installer wrote, and a sort would move it for no reason anybody asked for.
func TestAddAppends(t *testing.T) {
	out, _, err := Add([]byte(installed), "test", "age1third")
	if err != nil {
		t.Fatal(err)
	}
	if got := recipients(t, out); !slices.Equal(got, []string{"age1keeper", "age1backup", "age1third"}) {
		t.Errorf("recipients = %v", got)
	}
}

// Adding one already there rewrites nothing, so a command run twice does not
// reseal the store the second time.
func TestAddingOneAlreadyThereChangesNothing(t *testing.T) {
	out, added, err := Add([]byte(installed), "test", "age1backup")
	if err != nil {
		t.Fatal(err)
	}
	if added {
		t.Error("reported an addition that was already there")
	}
	if string(out) != installed {
		t.Errorf("the file was rewritten:\n%s", out)
	}
}

func TestRemove(t *testing.T) {
	out, removed, err := Remove([]byte(installed), "test", "age1backup")
	if err != nil || !removed {
		t.Fatalf("remove: %v (removed %v)", err, removed)
	}
	if got := recipients(t, out); !slices.Equal(got, []string{"age1keeper"}) {
		t.Errorf("recipients = %v", got)
	}
}

func TestRemovingOneThatIsNotThereChangesNothing(t *testing.T) {
	out, removed, err := Remove([]byte(installed), "test", "age1nobody")
	if err != nil {
		t.Fatal(err)
	}
	if removed {
		t.Error("reported a removal that never happened")
	}
	if string(out) != installed {
		t.Errorf("the file was rewritten:\n%s", out)
	}
}

// A rule naming nobody encrypts to nobody, and sops says so only at the next
// file it writes, by which time the command that caused it is long finished.
func TestTheLastRecipientCannotBeRemoved(t *testing.T) {
	one, _, err := Remove([]byte(installed), "test", "age1backup")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Remove(one, "test", "age1keeper"); err == nil {
		t.Error("emptied the recipient list")
	}
}

// The shorthand is what a hand-edited file often carries.  sops takes a
// comma-separated string there and nowhere else, so an edit has to read one and
// may write the list form back.
func TestTheAgeShorthandIsEditable(t *testing.T) {
	for _, src := range []string{
		"creation_rules:\n  - age:\n      - age1keeper\n",
		"creation_rules:\n  - age: age1keeper\n",
		"creation_rules:\n  - age: age1keeper,age1backup\n",
	} {
		t.Run(src, func(t *testing.T) {
			out, added, err := Add([]byte(src), "test", "age1third")
			if err != nil || !added {
				t.Fatalf("add: %v (added %v)", err, added)
			}
			if got := recipients(t, out); !slices.Contains(got, "age1third") ||
				!slices.Contains(got, "age1keeper") {
				t.Errorf("recipients = %v", got)
			}
		})
	}
}

// Every one of these leaves two answers to "which list is the recipient list".
// A writer that picked one would drop every reader named in the other at the
// next reseal, silently and unrecoverably by re-running.
func TestTheAmbiguousShapesAreRefused(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
		says string
	}{
		{
			"two creation rules",
			"creation_rules:\n  - path_regex: a$\n    age: [age1a]\n  - path_regex: b$\n    age: [age1b]\n",
			"path_regex",
		},
		{
			"a split data key",
			"creation_rules:\n  - shamir_threshold: 2\n    key_groups:\n      - age: [age1a]\n      - age: [age1b]\n",
			"shamir_threshold",
		},
		{
			"the shorthand beside key groups, of which sops reads only one",
			"creation_rules:\n  - age: [age1a]\n    key_groups:\n      - age: [age1b]\n",
			"remove the 'age:' line",
		},
		{
			"more than one key group",
			"creation_rules:\n  - key_groups:\n      - age: [age1a]\n      - age: [age1b]\n",
			"key groups",
		},
		{
			"recipients pulled in by merge",
			"creation_rules:\n  - key_groups:\n      - age: [age1a]\n        merge:\n          - age: [age1b]\n",
			"merge",
		},
		{"no creation rules at all", "other_key: 1\n", "no creation rule"},
		{"an empty file", "", "empty"},
		{
			"a rule naming no age recipient",
			"creation_rules:\n  - path_regex: a$\n    pgp: ABC\n",
			"age",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := Add([]byte(tc.src), "test", "age1third")
			if err == nil {
				t.Fatal("accepted a file whose recipient list is ambiguous")
			}
			if !strings.Contains(err.Error(), tc.says) {
				t.Errorf("error does not say why: %v", err)
			}
		})
	}
}

// The written file is read back before it is handed over.  This one decides who
// can open every managed value, and a write that produced YAML sops rejects
// leaves a host whose next encrypt fails with the store already sealed.
func TestWhatIsWrittenLoadsAgain(t *testing.T) {
	out, _, err := Add([]byte(installed), "test", "age1third")
	if err != nil {
		t.Fatal(err)
	}
	rules, err := Parse(out, "test")
	if err != nil {
		t.Fatalf("the edit does not load: %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("%d rules after an edit, want 1", len(rules))
	}
}
