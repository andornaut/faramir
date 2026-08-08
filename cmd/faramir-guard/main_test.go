package main

import (
	"os"
	"path/filepath"
	"testing"
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

func TestDeniedCommands(t *testing.T) {
	for _, cmd := range []string{
		"ansible-vault view group_vars/all/vault.yml",
		"sops -d secrets.sops.yml",
		"sops --decrypt secrets.sops.yml",
		"age -d < file",
		"age-keygen",
		"printenv",
		"printenv ROUTER_PW",
		"env",
		"cat /proc/self/environ",
		"cat /etc/faramir/config.toml",
		"tail /var/log/faramir/audit.log",
		"sudo -u faramir-keeper cat /etc/faramir/age.key",
		"cat ~/.ssh/id_rsa",
		"find / -name age.key",
		"declare -x",
		"vault kv get secret/foo",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("not denied: %q", cmd)
		}
	}
}

func TestAllowedCommands(t *testing.T) {
	for _, cmd := range []string{
		"ls -la",
		"git status",
		"ansible-playbook site.yml --check",
		"grep -r TODO .",
		"echo hello",
		// Piping env somewhere narrows it rather than dumping it into context.
		"env | grep -c PATH",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}
}

// The lookahead Python used is "(?!.*\|)"; RE2 gets "[^|]*$".  Both mean "env
// with no pipe after it", so the piped form stays allowed and the bare form
// stays denied.
func TestEnvLookaheadTranslation(t *testing.T) {
	if _, denied := decide("env"); !denied {
		t.Error("bare env was allowed")
	}
	if _, denied := decide("env | grep FOO"); denied {
		t.Error("piped env was denied")
	}
}

// faramir is the sanctioned path, so patterns inside its own arguments must
// not match.
func TestFaramirInvocationsAreNotScanned(t *testing.T) {
	for _, cmd := range []string{
		"faramir run --env ROUTER_PW=secret://home/router/admin -- printenv ROUTER_PW",
		"sudo faramir status",
		"faramir list-secrets",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}
}

// Stripping stops at the first separator: anything past it is a separate
// command the faramir prefix does not sanction.
func TestStrippingStopsAtASeparator(t *testing.T) {
	for _, cmd := range []string{
		"faramir status; printenv",
		"faramir status && printenv",
		"faramir status | printenv",
		"sudo faramir status; cat /etc/faramir/config.toml",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("a command past the separator slipped through: %q", cmd)
		}
	}
}

// The prefix sanctions the faramir CLI, not the daemons.  "faramir\b" also
// matched the hyphen in "faramir-broker", which stripped these before the deny
// list ever saw them and left that rule unable to fire at all.
func TestTheDaemonsAreNotSanctionedByThePrefix(t *testing.T) {
	for _, cmd := range []string{
		"sudo faramir-broker --check",
		"sudo faramir-keeper --check",
		"sudo faramir-exec --version",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("the prefix sanctioned a daemon invocation: %q", cmd)
		}
	}
}

// Requiring whitespace after "faramir" must not break a chain of them: the
// separator is left in place, so the second call still starts at one.
func TestEveryCallInAChainIsStripped(t *testing.T) {
	cmd := "faramir status; faramir run --env A=secret://a -- printenv A"
	if pattern, denied := decide(cmd); denied {
		t.Errorf("wrongly denied %q (pattern %q)", cmd, pattern)
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
