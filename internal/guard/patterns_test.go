package guard

import (
	"regexp"
	"strings"
	"testing"

	"github.com/andornaut/faramir/internal/denyrules"
	"github.com/andornaut/faramir/internal/install"
)

// The shipped file is a template, so the paths it refuses are the ones an
// install writes into it. Rendered against the compiled defaults.
func renderShippedBytes() ([]byte, error) {
	// install's own rendering rather than a second one here: the file now carries
	// generated rules, and a test that built it another way would assert on rules
	// nobody installs.
	return install.RenderDenyPatterns(install.Layout{
		ConfigDir:  install.DefaultConfigDir,
		BinDir:     install.DefaultBinDir,
		LibexecDir: install.DefaultLibexecDir,
		LogDir:     install.DefaultLogDir,
		BrokerUser: install.DefaultBrokerUser,
		KeeperUser: install.DefaultKeeperUser,
		ExecUser:   install.DefaultExecUser,
	})
}

func renderShipped(t *testing.T) string {
	t.Helper()
	data, err := renderShippedBytes()
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

func shippedLines(t *testing.T) []string {
	t.Helper()
	data := []byte(renderShipped(t))
	var out []string
	for line := range strings.SplitSeq(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			out = append(out, line)
		}
	}
	return out
}

// A fallback weaker than the shipped list turns an install problem into a
// silent gap.
//
// Byte equality is also what makes one compile check enough for both. RE2 has
// no lookahead or backreferences, and a pattern that fails to compile is
// skipped at load rather than reported, but TestEveryFallbackPatternCompiles
// asserts that none of the fallback is skipped, and equality carries that to
// the shipped file.
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

// Every refusal explains itself with the reason it was actually refused for.
//
// The deny list holds two kinds of rule and they need different messages. A
// read rule is about what the command would disclose, and faramir run is the
// way to proceed. A rule about faramir's own files, accounts or units discloses
// nothing, and faramir run is not a remedy there: it runs as an account with
// less reach, so following that advice either hits a permission error or, where
// the executor does have reach, does the thing that was refused.
func TestARefusalExplainsWhyItWasRefused(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    string
	}{
		// Disclosure: what the command would put in the conversation.
		{"sops -d /etc/faramir/secrets/db.sops.yml", advice},
		{"cat /etc/faramir/secrets/db.sops.yml", advice},
		{"sudo -u faramir-keeper cat /etc/faramir/age.key", advice},
		// faramir's own. Nothing here is disclosed; something is changed or stopped.
		{"rm /etc/faramir/age.key", adviceOwn},
		{"echo x > /etc/faramir/config.toml", adviceOwn},
		{"systemctl stop faramir-broker.socket", adviceOwn},
		{"rm ~/.config/opencode/plugin/faramir.js", adviceOwn},
		{"sed -i s/x/y/ ~/.pi/agent/extensions/faramir.ts", adviceOwn},
		// The operator's. Every faramir subcommand under sudo, the daemons and the
		// escalation channel among them: an agent has no root to run one with, and
		// a refusal saying so is more use than one about disclosure.
		{"sudo faramir keeper", adviceOperator},
		{"sudo faramir sudo approve abc123", adviceOperator},
		{"sudo faramir sudo ls", adviceOperator},
		{"sudo faramir sudo watch", adviceOperator},
		{"sudo faramir sudo reject abc123", adviceOperator},
		{"sudo faramir reader add age1abc", adviceOperator},
		{"sudo faramir reader reseal", adviceOperator},
		{"sudo faramir access --read /etc/faramir/age.key", adviceOperator},
		{"sudo faramir doctor", adviceOperator},
		// And the same set unprivileged, which is where an agent meets it.
		{"faramir doctor", adviceOperator},
		{"faramir logs", adviceOperator},
		{"faramir vault edit app", adviceOperator},
		{"faramir uninstall", adviceOperator},
	} {
		t.Run(tc.command, func(t *testing.T) {
			pattern, denied := decide(tc.command)
			if !denied {
				t.Fatalf("%q was not refused, so this says nothing about its message", tc.command)
			}
			if got := adviceFor(pattern, tc.command); got != tc.want {
				t.Errorf("%q was explained with the wrong message (pattern %s): a refusal "+
					"naming the wrong remedy sends the agent somewhere that cannot help",
					tc.command, pattern)
			}
		})
	}
}

// A pattern added to the list gets classified by this test rather than by
// whichever branch it happens to fall into. The counts are the forcing function:
// changing the list fails here until somebody says which message the new rule
// carries.
//
// Counted against a command naming this install's own directory, which is the
// half of the generated write and redirect rules that carries the ownership
// message. The other half is
// TestAWriteToADeclaredPathIsNotFaramirsOwn.
func TestEveryPatternIsClassifiedOnPurpose(t *testing.T) {
	counts := map[string]int{}
	for _, pattern := range fallback {
		counts[adviceFor(pattern, "rm /etc/faramir/age.key")]++
	}
	for _, tc := range []struct {
		name  string
		which string
		want  int
	}{
		// Seven: the generated write and redirect rules, the binary's two, the
		// plugin files' two, and systemctl.
		{"faramir's own", adviceOwn, 7},
		{"the operator's", adviceOperator, 2},
	} {
		if counts[tc.which] != tc.want {
			t.Errorf("%d of %d patterns explain themselves as %s, want %d. A rule was "+
				"added or moved: decide which message it should carry, add it to "+
				"TestARefusalExplainsWhyItWasRefused, and update this count",
				counts[tc.which], len(fallback), tc.name, tc.want)
		}
	}
}

// The generated write and redirect rules carry every subject: this install's own
// directories and the paths the operator declared or linked. Which one matched
// is in the command rather than in the pattern, and an agent told that
// /srv/luks.key is "faramir's own file" is told something false about the
// operator's own secret.
func TestAWriteToADeclaredPathIsNotFaramirsOwn(t *testing.T) {
	for _, pattern := range denyrules.For([]string{denyrules.Dir("/srv/luks.key")}) {
		for _, command := range []string{
			"rm /srv/luks.key",
			"cat /srv/luks.key",
			"echo x > /srv/luks.key",
		} {
			if !regexp.MustCompile(pattern).MatchString(command) {
				continue
			}
			if got := adviceFor(pattern, command); got != advice {
				t.Errorf("%q was explained as faramir's own; it is the operator's, "+
					"and the remedy for it is faramir run rather than the operator",
					command)
			}
		}
	}
}
