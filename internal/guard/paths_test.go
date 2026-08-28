package guard

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// The agents with no rule file of their own are refused a path here rather than
// by a matcher of their own, so this is the only thing standing between their
// file tools and the paths this install names. It used to be JavaScript sliced
// out of pi's extension and run by node; the cases came with it.
//
// A linked path names a FILE. A list matched only as a directory prefix refuses
// everything under it and not the file itself, which is the one path the entry
// exists for.
func TestTheGuardRefusesAPathHoweverItIsSpelled(t *testing.T) {
	// The rules this host actually installed, which is what the guard matches
	// against. A host with none renders the compiled defaults, and those name
	// this install's own directories either way.
	const dir = "/etc/faramir"
	for _, tc := range []struct {
		name  string
		path  string
		block bool
	}{
		{"this install's own key", dir + "/age.key", true},
		{"its directory itself", dir, true},

		// Each of these names the refused file and matches no literal rule about
		// it, so each is a way past one.
		{"a dot segment", dir + "/./age.key", true},
		{"a parent and back", dir + "/../faramir/age.key", true},
		{"a doubled separator", dir + "//age.key", true},
		{"a leading doubled separator", "/" + dir + "/age.key", true},

		{"an unrelated file", "/srv/app/notes.txt", false},
		// The subject is bounded, so a sibling whose name merely starts the same
		// way is not covered.
		{"a sibling of the refused directory", dir + "-notes/id", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, blocked := refusedPath(map[string]any{"file_path": tc.path})
			if blocked != tc.block {
				t.Errorf("refused(%q) = %v, want %v", tc.path, blocked, tc.block)
			}
		})
	}
}

// A "~" is the operator's home written the way a person writes it, and the
// rules carry the real path. Asserted as an equivalence: which paths a host
// refuses is what its operator declared, so naming one would test the config.
func TestTheTildeAndAbsoluteFormsAgree(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil || home == "/" {
		t.Skip("no home to expand against")
	}
	for _, rest := range []string{"/.ssh/id_ed25519", "/.luks/luks.key", "/src/app/main.go"} {
		t.Run(rest, func(t *testing.T) {
			_, tilde := refusedPath(map[string]any{"p": "~" + rest})
			_, absolute := refusedPath(map[string]any{"p": filepath.Join(home, rest)})
			if tilde != absolute {
				t.Errorf("~%s refused=%v but %s refused=%v", rest, tilde,
					filepath.Join(home, rest), absolute)
			}
		})
	}
}

// A name and a relative path carry no separator to anchor on and never carry a
// space either, which is what keeps a declared name covered. Prose is what
// falls outside: a sentence naming a file is not a call to open it.
func TestWhatCountsAsAPathArgument(t *testing.T) {
	for _, tc := range []struct {
		name string
		arg  string
		want bool
	}{
		{"absolute", "/etc/faramir/age.key", true},
		{"absolute, with a space in it", "/etc/my files/age.key", true},
		{"under the home", "~/.ssh/id_rsa", true},
		{"a bare name", "age.key", true},
		{"a relative path", "faramir/age.key", true},
		{"prose", "the key lives at /etc/faramir/age.key", false},
		{"prose with no path at all", "hello world", false},
		{"a line of a file", "key = value\n", false},
		{"nothing", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := looksLikePath(tc.arg); got != tc.want {
				t.Errorf("looksLikePath(%q) = %v, want %v", tc.arg, got, tc.want)
			}
		})
	}
}

// Every string in the call, at any depth: a tool taking one path and a tool
// taking a list of them are the same question, and enumerating tool schemas is
// how one gets missed.
func TestEveryStringInTheCallIsConsidered(t *testing.T) {
	got := pathsIn(map[string]any{
		"a": "one",
		"b": []any{"two", map[string]any{"c": "three"}},
		"d": 4,
	}, 0)
	if strings.Join(got, ",") != "one,two,three" {
		t.Errorf("pathsIn = %v, want the three strings in key order", got)
	}
}
