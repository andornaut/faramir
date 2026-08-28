package guard

import (
	"os"
	"os/user"
	"path/filepath"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/config"
	"github.com/andornaut/faramir/internal/install"
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

// blockOneFileUnderTheHome renders this install's rules with one [[secret.block]]
// entry naming a file in the account's own home, points the guard at them, and
// returns the path it declared.
//
// A home path rather than one of this install's directories, because expanding
// "~" is the only thing the spellings do that normalising a command line does
// not, so a rule under /etc would leave it unasserted.
func blockOneFileUnderTheHome(t *testing.T) string {
	t.Helper()
	me, err := user.Current()
	if err != nil || me.Username == "" {
		t.Skip("no account to render the rules against")
	}
	return blockAFileAs(t, me.Username)
}

// blockAFileAs is the same against a named agent account, which decides whether
// the rendered rule carries the home spellings at all: HomeSpellings emits the
// "~", "$HOME" and "${HOME}" forms only where the path sits under the home it
// was given, and the layout's is looked up from this name.
func blockAFileAs(t *testing.T, agentUser string) string {
	t.Helper()
	secret := filepath.Join(guardHome(), ".ssh", "id_ed25519")
	rules, err := install.RenderDenyPatterns(install.Layout{
		ConfigDir:  install.DefaultConfigDir,
		BinDir:     install.DefaultBinDir,
		LibexecDir: install.DefaultLibexecDir,
		LogDir:     install.DefaultLogDir,
		BrokerUser: install.DefaultBrokerUser,
		KeeperUser: install.DefaultKeeperUser,
		ExecUser:   install.DefaultExecUser,
		AgentUser:  agentUser,
		Blocked:    []config.BlockedPath{{Path: secret}},
	})
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "deny-patterns.txt")
	if err := os.WriteFile(file, rules, 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", file)
	return secret
}

// The guard expands "~" itself, and that is the half of the cover that holds
// when the rendered rule has lost the home spellings.
//
// A rule carries the "~", "$HOME" and "${HOME}" forms only where the layout
// knew which home the path was under, which is `[server] agent_user` resolving
// to an account. Unset, removed, or naming a different account than the guard
// runs as, the rule is the absolute path alone, and a file tool handed the
// tilde form matches nothing in it. So the expansion here is not a second copy
// of what the rules already say: it is what covers a host whose rules were
// rendered without a home to name.
func TestTheTildeFormIsRefusedWhereTheRulesLostTheHomeSpellings(t *testing.T) {
	if guardHome() == "" {
		t.Skip("no home to expand against")
	}
	for _, agentUser := range []string{"", "root"} {
		t.Run("agent_user "+agentUser, func(t *testing.T) {
			declared := blockAFileAs(t, agentUser)
			if _, refused := refusedPath(map[string]any{"p": declared}); !refused {
				t.Fatalf("the declared path is not refused as written: %s", declared)
			}
			if _, refused := refusedPath(map[string]any{"p": "~/.ssh/id_ed25519"}); !refused {
				t.Error("the tilde form is not refused, so a rule rendered without a home " +
					"leaves it uncovered and the guard's own expansion is doing nothing")
			}
		})
	}
}

// A "~" is the operator's home written the way a person writes it, and the
// rules carry the real path, so the guard expands one before it asks.
//
// Asserted against a rule that actually names a file under this home. An
// equivalence alone passes when neither form is refused, which is every host
// whose rules name nothing under a home: it agrees, and it agrees about
// nothing.
func TestTheTildeFormIsRefusedAsTheAbsoluteOneIs(t *testing.T) {
	home := guardHome()
	if home == "" {
		t.Skip("no home to expand against")
	}
	secret := blockOneFileUnderTheHome(t)

	// The absolute form first: if the rule does not reach it, the tilde case
	// below would agree with it and prove nothing, which is the failure this
	// replaced.
	if _, refused := refusedPath(map[string]any{"p": secret}); !refused {
		t.Fatalf("the declared path is not refused as written, so this asserts nothing: %s", secret)
	}
	if _, refused := refusedPath(map[string]any{"p": "~/.ssh/id_ed25519"}); !refused {
		t.Error("the tilde form is not refused, so a path written the way a person writes it is a way past the rule")
	}
	// And an unrelated file under the same home is left alone, or the rule would
	// be refusing the home rather than the file in it.
	if _, refused := refusedPath(map[string]any{"p": "~/src/app/main.go"}); refused {
		t.Error("an ordinary file under the home is refused, so the rule is wider than the entry")
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
