package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
)

// Point every test at the repo's own patterns rather than at whatever is
// installed under /usr/local/libexec.  Rendered first, because the shipped file
// is a template whose path rules match nothing unexpanded.
func TestMain(m *testing.M) {
	cleanup := func() {}
	if data, err := renderShippedBytes(); err == nil {
		if dir, err := os.MkdirTemp("", "faramir-guard-patterns"); err == nil {
			cleanup = func() { _ = os.RemoveAll(dir) }
			path := filepath.Join(dir, "deny-patterns.txt")
			if os.WriteFile(path, data, 0o644) == nil {
				_ = os.Setenv("FARAMIR_DENY_PATTERNS", path)
			}
		}
	}
	// Not deferred: os.Exit would skip it.
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// The prefix sanctions the operator's subcommands, not the roles systemd runs.
// Both spellings, since an unconverged host still has the old per-role
// binaries.
func TestTheDaemonsAreNotSanctionedByThePrefix(t *testing.T) {
	cmds := make([]string, 0, len(cli.Internal)*2)
	for _, role := range cli.Internal {
		cmds = append(cmds,
			"sudo faramir "+role+" --check",
			"sudo faramir-"+role+" --check",
		)
	}
	for _, cmd := range cmds {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the prefix sanctioned a daemon invocation: %q", cmd)
		}
	}
}

// Answering an escalation is the operator's, and this hook gates the agent's
// shell rather than the operator's terminal: an agent that could approve the
// request it raised is the whole boundary gone.  Both the helper sudo runs and
// the subcommand a human types are denied here.
func TestTheAgentCannotAnswerItsOwnEscalation(t *testing.T) {
	for _, cmd := range []string{
		"sudo faramir approve",
		"sudo faramir approve a1b2c3",
		"sudo faramir approve --watch",
		"sudo -n faramir approve a1b2c3",
		"sudo faramir pam-approve",
		// Reading what is waiting is as much the operator's as answering it: the
		// command an agent would have to run to learn there is a question at all.
		"sudo faramir escalations",
		"sudo faramir escalations --watch",
		"sudo faramir deny",
		"sudo faramir deny a1b2c3",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the agent may answer an escalation: %q", cmd)
		}
	}
	// Without sudo it reaches a broker that refuses it anyway, and denying it here
	// would only trade the refusal for a worse message.
	if pattern, denied := decide("faramir approve --watch"); denied {
		t.Errorf("wrongly denied an unprivileged approve (pattern %q)", pattern)
	}
	// `escalations`, `approve` and `deny` are the three carved out of the sudo
	// sanction, and the only three: every other subcommand still has its own
	// arguments left unscanned under sudo.
	if pattern, denied := decide("sudo faramir secrets edit faramir://a/b"); denied {
		t.Errorf("the sudo sanction lost more than the answering subcommands (pattern %q)",
			pattern)
	}
}

// Naming the sanctioned subcommands is only safe if every one is named: one
// left out has its arguments scanned.
func TestEveryOperatorSubcommandIsSanctioned(t *testing.T) {
	for _, name := range cli.Operator {
		// A ref in the arguments is the thing an unsanctioned call trips on.
		cmd := "faramir " + name + " --env A=faramir://a"
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied a sanctioned subcommand: %q (pattern %q)", cmd, pattern)
		}
	}
}

// A patterns file that cannot be read must not disable the hook.
func TestFallbackIsUsedWhenThePatternsFileIsMissing(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if _, denied := decide("printenv"); !denied {
		t.Error("the fallback list did not apply")
	}
}

// A pattern that fails to compile is skipped at load, silently weakening the
// list.
func TestEveryFallbackPatternCompiles(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if got, want := len(loadPatterns()), len(fallback); got != want {
		t.Errorf("%d of %d fallback patterns compiled; the rest are RE2-incompatible", got, want)
	}
}

// The fallback names /etc/faramir and the documented ~/.config/faramir, so an
// install placed anywhere else would be refused by neither.  The directory is
// taken from where the daemons take it, so moving the config moves what the
// hook refuses instead of silently narrowing it.
func TestTheFallbackFollowsAMovedConfigDir(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	const moved = "/srv/elsewhere"
	command := "cat " + moved + "/config.toml"

	// Nothing else in the list matches this, so what follows is the derived
	// rule and not a coincidence.
	if _, denied := decide(command); denied {
		t.Fatalf("%q is already denied, so this test proves nothing", command)
	}

	t.Setenv("FARAMIR_CONFIG", moved+"/config.toml")

	if _, denied := decide(command); !denied {
		t.Errorf("%q is allowed with the config at %s", command, moved)
	}
	if _, denied := decide("rm -rf " + moved + "/secrets"); !denied {
		t.Error("writes to a moved config directory are allowed")
	}
}

// The documented per-operator placement, refused by name so that a store found
// in someone else's home is refused too, not only the one this host installed.
func TestTheFallbackNamesTheOperatorConvention(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	for _, command := range []string{
		"cat ~/.config/faramir/config.toml",
		"rm -f /home/someone/.config/faramir/secrets/x.sops.yml",
	} {
		if _, denied := decide(command); !denied {
			t.Errorf("%q is allowed", command)
		}
	}
}
