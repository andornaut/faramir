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
			cleanup = func() { os.RemoveAll(dir) }
			path := filepath.Join(dir, "deny-patterns.txt")
			if os.WriteFile(path, data, 0o644) == nil {
				os.Setenv("FARAMIR_DENY_PATTERNS", path)
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

// Naming the sanctioned subcommands is only safe if every one is named: one
// left out has its arguments scanned.
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

// A pattern that fails to compile is skipped at load, silently weakening the
// list.
func TestEveryFallbackPatternCompiles(t *testing.T) {
	t.Setenv("FARAMIR_DENY_PATTERNS", "/nonexistent/deny-patterns.txt")
	if got, want := len(loadPatterns()), len(fallback); got != want {
		t.Errorf("%d of %d fallback patterns compiled; the rest are RE2-incompatible", got, want)
	}
}
