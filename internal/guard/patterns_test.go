package guard

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"text/template"

	"github.com/andornaut/faramir/internal/install"
)

const shippedPatterns = "../../agent/hooks/deny-patterns.txt"

// The shipped file is a template: the paths worth refusing belong to an
// install, not to the source tree, so an operator who moved the config and the
// store into a home gets rules naming where they actually are.  Rendering it
// against the compiled defaults is what the fallback has to match, and is what
// the other tests here match against.
func renderShippedBytes() ([]byte, error) {
	data, err := os.ReadFile(shippedPatterns)
	if err != nil {
		return nil, err
	}
	tmpl, err := template.New("deny").Funcs(template.FuncMap{
		"regexQuote": regexp.QuoteMeta,
	}).Parse(string(data))
	if err != nil {
		return nil, err
	}
	var out strings.Builder
	if err := tmpl.Execute(&out, install.Layout{
		ConfigDir:  install.DefaultConfigDir,
		SecretsDir: install.DefaultConfigDir + "/secrets",
		BinDir:     install.DefaultBinDir,
		LibexecDir: install.DefaultLibexecDir,
		LogDir:     install.DefaultLogDir,
	}); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

func renderShipped(t *testing.T) string {
	t.Helper()
	data, err := renderShippedBytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// renderedFile writes the rendered patterns to a temp file and points the guard
// at it, so the deny tests exercise the same text an install would write.
func renderedFile(t *testing.T) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "deny-patterns.txt")
	if err := os.WriteFile(path, []byte(renderShipped(t)), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Setenv("FARAMIR_DENY_PATTERNS", path)
}

func shippedLines(t *testing.T) []string {
	t.Helper()
	data := []byte(renderShipped(t))
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
	renderedFile(t)

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

// The sops age key is the one an agent can actually reach: /etc/faramir/age.key
// is root-owned, but ~/.config/sops/age/keys.txt decrypts the same store and is
// readable by the uid the agent runs as.  It is spelled keys.txt, so every
// alternative that names a key by extension misses it.
func TestTheReachableAgeKeyIsDenied(t *testing.T) {
	renderedFile(t)

	for _, cmd := range []string{
		"cat /home/op/.config/sops/age/keys.txt",
		"awk '{print}' ~/.config/sops/age/keys.txt",
		`python3 -c "print(open('/home/op/.config/sops/age/keys.txt').read())"`,
		"cp ~/.config/sops/age/keys.txt /tmp/k",
		"tar cf - ~/.config/sops/age",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
}

// Writes to the broker's own files.  The store sits under a home and is
// writable by the agent's uid, and the hook's patterns decide what it refuses,
// so neutering either is a route to everything else.
func TestChangingTheBrokersOwnFilesIsDenied(t *testing.T) {
	renderedFile(t)

	for _, cmd := range []string{
		"rm -f /etc/faramir/age.key",
		"rm -f ~/.faramir/secrets/ansible-ctrl.sops.yml",
		"chmod 0644 /etc/faramir/age.key",
		"chown op /etc/faramir/age.key",
		"mv ~/.config/sops/age/keys.txt /tmp/k",
		`echo "" > /usr/local/libexec/faramir/deny-patterns.txt`,
		"cp /bin/true /usr/local/libexec/faramir/wrap.sh",
		// The binary itself, which is the hook as well as the CLI now.
		"cp /bin/true /usr/local/bin/faramir",
		"sops set ~/.faramir/secrets/x.sops.yml '[\"a\"]' '\"b\"'",
		"sops -e -i secrets.yml",
		"systemctl edit faramir-broker",
	} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}

	// The binary is named as a path, not as its directory: installing an
	// unrelated tool into the same directory is ordinary work.
	for _, cmd := range []string{
		"cp /bin/true /usr/local/bin/jq",
		"install -m 0755 yq /usr/local/bin/yq",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}

	// Writing documentation that mentions a protected path is not a write to
	// it, which is why the redirect rule matches the target word alone rather
	// than the rest of the line.  A heredoc fed through "cat" is still refused,
	// by the reader rule and not this one: that rule cannot tell a command that
	// would read a path from one that merely names it, which is the limitation
	// the file's header describes.
	for _, cmd := range []string{
		"echo 'see /etc/faramir/config.toml' >> README.md",
		"printf '%s\\n' 'store lives in ~/.faramir/secrets' >> docs/scope.md",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("shipped file wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}
}

// A file whose name merely ends in .env is not a dotenv.  faramir.env holds
// refs and no values, and refusing to grep it taught the agent to reach for a
// tool the hook does not see instead.
func TestNamingAnEnvSuffixedFileIsNotADump(t *testing.T) {
	renderedFile(t)

	for _, cmd := range []string{
		"grep -n hamcp faramir.env",
		"cat faramir.env",
		"wc -l faramir.env",
	} {
		if pattern, denied := decide(cmd); denied {
			t.Errorf("shipped file wrongly denied %q (pattern %q)", cmd, pattern)
		}
	}
	// The dotenv itself still is one.
	for _, cmd := range []string{"cat .env", "cat ./.env", "cat app/.env.local"} {
		if _, denied := decide(cmd); !denied {
			t.Errorf("shipped file did not deny %q", cmd)
		}
	}
}

// faramir_run's own description tells the model that transformed output
// (base64, rev, cut) is a policy violation rather than a puzzle.  Denying cat
// while allowing the encoders makes that claim false and the rule look
// arbitrary, which is the opposite of what a hook that teaches should do.
func TestReadingKeyMaterialThroughAnEncoderIsDeniedToo(t *testing.T) {
	renderedFile(t)

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

	// The guard must not block an ordinary operator step.  "sed" is
	// deliberately absent from the reader list: it edits far more often than it
	// dumps.
	for _, cmd := range []string{
		`sed -i 's/^nocows.*/nocows = True/' ansible.cfg`,
		"base64 /tmp/screenshot.png",
		"ansible-playbook site.yml --check",
	} {
		if _, denied := decide(cmd); denied {
			t.Errorf("shipped file denied %q, which is not a disclosure", cmd)
		}
	}
}
