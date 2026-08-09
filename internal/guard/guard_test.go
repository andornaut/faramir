package guard

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/andornaut/faramir/internal/cli"
)

// Point every test at the shipped file rather than at whatever this host has
// installed under /usr/local/libexec.  Without this the suite grades the
// machine it runs on: a stale installed file passes tests that the repo's own
// patterns would fail, and CI (which has no installed file, so gets the
// fallback) disagrees with the developer's box.
// Rendered first: the shipped file is a template, so the paths it refuses are
// the ones an install writes into it.  Reading it raw would leave the path
// rules as unexpanded template text, which matches nothing.
func TestMain(m *testing.M) {
	cleanup := func() {}
	if data, err := renderShippedBytes(); err == nil {
		if dir, err := os.MkdirTemp("", "faramir-guard-patterns"); err == nil {
			cleanup = func() { os.RemoveAll(dir) }
			path := filepath.Join(dir, "deny-patterns.txt")
			if os.WriteFile(path, data, 0o644) == nil {
				os.Setenv("FARAMIR_DENY_PATTERNS", path)
			}
		}
	}
	// Not deferred: os.Exit would skip it, leaving a temp directory per run.
	code := m.Run()
	cleanup()
	os.Exit(code)
}

// The prefix sanctions the operator's subcommands, not the roles systemd runs.
// Both spellings are checked: the daemons are subcommands of the one binary now,
// and a host that has not converged still has the old per-role binaries on disk.
func TestTheDaemonsAreNotSanctionedByThePrefix(t *testing.T) {
	var cmds []string
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

// The other half of the rule above: naming the sanctioned subcommands is only
// safe if every one of them is actually named.  A subcommand left out has its
// arguments scanned, so `faramir run --env A=secret://a` would be refused.
func TestEveryOperatorSubcommandIsSanctioned(t *testing.T) {
	for _, name := range cli.Operator {
		// A ref in the arguments is the thing an unsanctioned call trips on.
		cmd := "faramir " + name + " --env A=secret://a"
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

// Every fallback pattern must compile under RE2.  A pattern that does not is
// skipped at load, which would silently weaken the list.
func TestEveryFallbackPatternCompiles(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if got, want := len(loadPatterns()), len(fallback); got != want {
		t.Errorf("%d of %d fallback patterns compiled; the rest are RE2-incompatible", got, want)
	}
}
