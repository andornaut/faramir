package main

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

const shippedPatterns = "../../agent/hooks/deny-patterns.txt"

func shippedLines(t *testing.T) []string {
	t.Helper()
	data, err := os.ReadFile(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// Every shipped pattern must compile under RE2.  Python's `re` accepts
// lookahead and backreferences; Go's regexp does not, and a pattern that fails
// to compile is skipped at load, silently weakening the list.  This is the
// exact failure mode the port could introduce, so it is asserted rather than
// assumed.
func TestEveryShippedPatternCompilesUnderRE2(t *testing.T) {
	lines := shippedLines(t)
	if len(lines) == 0 {
		t.Fatal("no patterns in the shipped file")
	}
	for _, pattern := range lines {
		if _, err := regexp.Compile("(?i)" + pattern); err != nil {
			t.Errorf("shipped pattern does not compile under RE2: %q: %v", pattern, err)
		}
	}
}

// The shipped file and the built-in fallback have to agree.  A fallback weaker
// than the shipped list turns an install problem into a silent gap.
func TestTheFallbackMatchesTheShippedFile(t *testing.T) {
	shipped := shippedLines(t)
	if len(shipped) != len(fallback) {
		t.Fatalf("shipped file has %d patterns, fallback has %d", len(shipped), len(fallback))
	}
	for i := range shipped {
		if shipped[i] != fallback[i] {
			t.Errorf("pattern %d differs:\n  shipped:  %s\n  fallback: %s", i, shipped[i], fallback[i])
		}
	}
}

// The shipped file must actually deny the things it exists to deny, loaded from
// disk rather than from the fallback.
func TestTheShippedFileDeniesTheDocumentedCases(t *testing.T) {
	abs, err := filepath.Abs(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", abs)

	for _, cmd := range []string{"printenv", "env", "sops -d x.sops.yml", "age-keygen"} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
	// Every private key name, not the ones a clever character class happened to
	// reach.  id_ed25519 is what ssh-keygen produces by default and was the one
	// the earlier pattern missed.
	for _, name := range []string{"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519"} {
		for _, tool := range []string{"cat", "base64", "strings"} {
			cmd := tool + " ~/.ssh/" + name
			if _, denied := decide(cmd); !denied {
				t.Errorf("shipped file did not deny %q", cmd)
			}
		}
	}

	// Ordinary shell that earlier rules refused.  Each of these was a real
	// false positive: env with assignments is not a dump, a rule spanning a
	// pipe matched the wrong side of it, listing a directory reads nothing,
	// and age-keygen -o writes a key without printing one.
	for _, cmd := range []string{
		"env FOO=1 make build",
		"env DEBIAN_FRONTEND=noninteractive apt-get install -y jq",
		"cat notes.md | grep credentials",
		"ls /var/log/faramir",
		"journalctl -u faramir-broker -n 50",
		"age-keygen -o /tmp/throwaway.key",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("shipped file wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}

	// The dumps those rules are actually for.
	for _, cmd := range []string{
		"env", "env -i", "age-keygen", "cat /var/log/faramir/audit.log",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}

	// Managing a unit is an operator action the docs prescribe; running the
	// daemon, or running as its account, is not.  Stopping the broker is denied
	// with the second group because the wrapper fails open without it.
	for _, cmd := range []string{
		"sudo faramir-keeper",
		"sudo -E faramir-broker -c /etc/faramir/config.toml",
		"sudo -u faramir-exec ls /srv",
		"sudo systemctl stop faramir-broker",
		"systemctl disable faramir-keeper",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
	for _, cmd := range []string{
		"sudo systemctl restart faramir-keeper",
		"sudo systemctl status faramir-broker",
		"systemctl show faramir-exec",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("shipped file wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}

	// A managed file's own name matches none of the credential-shaped
	// alternatives: "secrets/" is a directory, so "secrets?\." does not fire,
	// and the path holds no "vault", ".env" or "credentials" either.  Coverage
	// comes from /etc/faramir sitting in the same alternation as those, which
	// is what puts it in front of every encoder rather than only the handful of
	// tools a narrower rule would name.
	for _, tool := range []string{"cat", "base64", "xxd", "strings", "rev", "od"} {
		cmd := tool + " /etc/faramir/secrets/ansible-ctrl.sops.yml"
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
	if _, denied := decide("env | grep PATH"); denied {
		t.Error("shipped file denied a piped env")
	}
}

// faramir_run's own description tells the model that transformed output
// (base64, rev, cut) is a policy violation rather than a puzzle.  Denying cat
// while allowing the encoders makes that claim false and the rule look
// arbitrary, which is the opposite of what a hook that teaches should do.
func TestReadingKeyMaterialThroughAnEncoderIsDeniedToo(t *testing.T) {
	abs, err := filepath.Abs(shippedPatterns)
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", abs)

	for _, cmd := range []string{
		"cat /var/lib/faramir-keeper/age.key",
		"base64 /var/lib/faramir-keeper/age.key",
		"base32 ~/.ssh/id_rsa",
		"hexdump -C secrets.yml",
		"rev group_vars/all/vault.sops.yml",
		"tac .env",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}

	// The migration runbook runs this, and the guard must not block a
	// documented operator step.  "sed" is deliberately absent from the reader
	// list: it edits far more often than it dumps.
	for _, cmd := range []string{
		`sed -i '/^vault_password_file/d' ansible.cfg`,
		"base64 /tmp/screenshot.png",
		"ansible-playbook site.yml --check",
	} {
		if _, denied := decide(cmd); denied {
			t.Errorf("shipped file denied %q, which is not a disclosure", cmd)
		}
	}
}
